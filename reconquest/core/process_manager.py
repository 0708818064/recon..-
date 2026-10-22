"""
RECONQUEST - Process Manager
Manages external tool execution with strict security controls, process group isolation,
resource limits, and real-time output capturing.
"""

import os
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from .logging_config import log_audit_event, get_audit_logger


class ProcessResult:
    """Encapsulates process completion data."""
    def __init__(self, return_code: int, stdout: str, stderr: str, duration: float, timed_out: bool = False):
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timed_out = timed_out

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out


class ManagedProcess:
    """Represents an active or completed background process."""
    def __init__(self, job_id: str, command: List[str], tool_name: str, target: str, timeout: int = 300, max_output_bytes: int = 5 * 1024 * 1024):
        self.job_id = job_id
        self.command = command
        self.tool_name = tool_name
        self.target = target
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

        self.process: Optional[subprocess.Popen] = None
        self.status = "pending"  # pending, running, completed, failed, cancelled, timed_out
        self.return_code: Optional[int] = None
        self.stdout_lines: List[str] = []
        self.stderr_lines: List[str] = []
        self.total_bytes = 0

        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.duration_seconds: float = 0.0

        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Spawn the process in a new process group for clean signal handling."""
        self.started_at = datetime.now(timezone.utc)
        self.status = "running"

        log_audit_event(
            action="PROCESS_EXECUTE",
            target=self.target,
            tool=self.tool_name,
            status="started",
            details={"command": " ".join(self.command), "job_id": self.job_id}
        )

        try:
            # os.setsid creates a new process session / process group
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid
            )

            # Start monitoring thread
            self._thread = threading.Thread(target=self._monitor, daemon=True)
            self._thread.start()
        except Exception as e:
            self.status = "failed"
            self.completed_at = datetime.now(timezone.utc)
            self.stderr_lines.append(f"Failed to spawn process: {str(e)}")
            log_audit_event(
                action="PROCESS_SPAWN_ERROR",
                target=self.target,
                tool=self.tool_name,
                status="failed",
                details={"error": str(e)}
            )

    def _monitor(self):
        """Worker thread that streams stdout/stderr and enforces limits."""
        start_time = time.time()

        def stream_pipe(pipe, target_list):
            for line in iter(pipe.readline, ''):
                with self._lock:
                    if self.total_bytes < self.max_output_bytes:
                        target_list.append(line)
                        self.total_bytes += len(line.encode('utf-8', errors='ignore'))
                    elif self.total_bytes >= self.max_output_bytes and not any("[RECONQUEST: Output truncated]" in l for l in target_list):
                        target_list.append("\n[RECONQUEST: Output truncated - Max output limit reached]\n")
            pipe.close()

        stdout_thread = threading.Thread(target=stream_pipe, args=(self.process.stdout, self.stdout_lines), daemon=True)
        stderr_thread = threading.Thread(target=stream_pipe, args=(self.process.stderr, self.stderr_lines), daemon=True)

        stdout_thread.start()
        stderr_thread.start()

        # Polling loop with timeout check
        timed_out = False
        while self.process.poll() is None:
            time.sleep(0.5)
            if time.time() - start_time > self.timeout:
                timed_out = True
                self.terminate()
                break

        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)

        self.duration_seconds = time.time() - start_time
        self.completed_at = datetime.now(timezone.utc)

        with self._lock:
            if timed_out:
                self.status = "timed_out"
                self.stderr_lines.append(f"\n[RECONQUEST: Execution timed out after {self.timeout}s]\n")
            elif self.status != "cancelled":
                self.return_code = self.process.returncode
                self.status = "completed" if self.return_code == 0 else "failed"

        log_audit_event(
            action="PROCESS_FINISHED",
            target=self.target,
            tool=self.tool_name,
            status=self.status,
            details={"duration": round(self.duration_seconds, 2), "return_code": self.return_code}
        )

    def terminate(self) -> bool:
        """Safely kill the entire process group with SIGTERM then SIGKILL."""
        if not self.process or self.process.poll() is not None:
            return True

        with self._lock:
            self.status = "cancelled"

        try:
            pgid = os.getpgid(self.process.pid)
            os.killpg(pgid, signal.SIGTERM)
            # Give short grace period
            time.sleep(0.5)
            if self.process.poll() is None:
                os.killpg(pgid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            return True
        except Exception as e:
            get_audit_logger().error(f"Error terminating process {self.job_id}: {e}")
            return False

    def get_output(self) -> Dict[str, Any]:
        """Fetch current state and buffered output."""
        with self._lock:
            return {
                "job_id": self.job_id,
                "tool_name": self.tool_name,
                "target": self.target,
                "command": " ".join(self.command),
                "status": self.status,
                "duration_seconds": round(self.duration_seconds if self.duration_seconds else (time.time() - (self.started_at.timestamp() if self.started_at else time.time())), 1),
                "return_code": self.return_code,
                "stdout": "".join(self.stdout_lines),
                "stderr": "".join(self.stderr_lines),
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": self.completed_at.isoformat() if self.completed_at else None
            }


class ProcessManager:
    """Central registry of executing jobs."""

    _active_jobs: Dict[str, ManagedProcess] = {}
    _lock = threading.Lock()

    @classmethod
    def start_job(cls, command: List[str], tool_name: str, target: str, timeout: int = 300) -> str:
        """Start a managed background tool execution and return its unique job_id."""
        job_id = str(uuid.uuid4())
        job = ManagedProcess(job_id=job_id, command=command, tool_name=tool_name, target=target, timeout=timeout)
        with cls._lock:
            cls._active_jobs[job_id] = job
        job.start()
        return job_id

    @classmethod
    def get_job(cls, job_id: str) -> Optional[ManagedProcess]:
        with cls._lock:
            return cls._active_jobs.get(job_id)

    @classmethod
    def cancel_job(cls, job_id: str) -> bool:
        with cls._lock:
            job = cls._active_jobs.get(job_id)
        if job:
            return job.terminate()
        return False

    @classmethod
    def list_jobs(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            return [job.get_output() for job in cls._active_jobs.values()]

    @classmethod
    def run_sync(cls, command: List[str], timeout: int = 30) -> ProcessResult:
        """Synchronous safe command execution for short queries (dig, whois, iw dev, etc.)."""
        start_time = time.time()
        try:
            res = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return ProcessResult(
                return_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                duration=time.time() - start_time,
                timed_out=False
            )
        except subprocess.TimeoutExpired as e:
            return ProcessResult(
                return_code=-1,
                stdout=e.stdout or "",
                stderr="Execution timed out.",
                duration=timeout,
                timed_out=True
            )
        except Exception as e:
            return ProcessResult(
                return_code=-1,
                stdout="",
                stderr=str(e),
                duration=time.time() - start_time,
                timed_out=False
            )
