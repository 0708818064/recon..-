/**
 * RECONQUEST - Core Frontend Interactive Application
 * Handles numbered navigation, terminal polling, modal popups, and scan execution.
 */

const ReconQuest = {
    state: {
        activeJobId: null,
        pollInterval: null,
        userLevel: 1,
        userXp: 0
    },

    init: function() {
        this.setupKeyboardShortcuts();
        this.setupSidebar();
        this.initClipboardButtons();
        console.log("%c[RECONQUEST]%c Tactical Reconnaissance Engine initialized.", "color:#00ff66;font-weight:bold;", "color:#00e5ff;");
    },

    /* CSRF Helper */
    getCSRFToken: function() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : '';
    },

    /* Universal API caller */
    apiCall: async function(url, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.getCSRFToken(),
            ...options.headers
        };
        try {
            const resp = await fetch(url, { ...options, headers });
            const data = await resp.json();
            return data;
        } catch (err) {
            console.error("API Error:", err);
            this.showToast("Network / Server connection error", "error");
            return { success: false, error: err.message };
        }
    },

    /* Toast Notifications */
    showToast: function(message, type = "info") {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let icon = "fa-circle-info";
        if (type === "success") icon = "fa-circle-check";
        if (type === "error") icon = "fa-triangle-exclamation";
        if (type === "warning") icon = "fa-triangle-exclamation";

        toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },

    /* Modal Management */
    showModal: function(title, bodyHtml, onConfirm = null) {
        const modal = document.getElementById('cyberModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');
        const confirmBtn = document.getElementById('modalConfirmBtn');

        modalTitle.innerText = title;
        modalBody.innerHTML = bodyHtml;
        modal.style.display = 'flex';

        confirmBtn.onclick = () => {
            if (onConfirm) onConfirm();
            this.closeModal();
        };
    },

    closeModal: function() {
        const modal = document.getElementById('cyberModal');
        if (modal) modal.style.display = 'none';
    },

    /* Clipboard Copy */
    copyToClipboard: function(text, label = "Command") {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast(`${label} copied to clipboard!`, "success");
        }).catch(err => {
            this.showToast("Failed to copy to clipboard", "error");
        });
    },

    initClipboardButtons: function() {
        document.querySelectorAll('[data-copy]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetText = btn.getAttribute('data-copy');
                this.copyToClipboard(targetText);
            });
        });
    },

    /* Sidebar toggle */
    setupSidebar: function() {
        const toggle = document.getElementById('sidebarToggle');
        const sidebar = document.getElementById('sidebar');
        if (toggle && sidebar) {
            toggle.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
            });
        }
    },

    /* Keyboard navigation: numbers [1] to [11] and [0] */
    setupKeyboardShortcuts: function() {
        window.addEventListener('keydown', (e) => {
            // Ignore if user is currently typing in an input or textarea
            if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
                return;
            }

            if (e.key === 'Escape') {
                this.closeModal();
                return;
            }

            // Check if there are numbered elements on the page with data-shortcut
            const targetEl = document.querySelector(`[data-key="${e.key}"]`);
            if (targetEl) {
                e.preventDefault();
                targetEl.click();
                this.showToast(`Selected option [${e.key}]`, "info");
            }
        });
    },

    /* Scan Poller */
    startScanMonitoring: function(jobId, terminalId = 'terminalStream') {
        this.state.activeJobId = jobId;
        const activeBadge = document.getElementById('activeBadge');
        if (activeBadge) activeBadge.style.display = 'flex';

        const terminal = document.getElementById(terminalId);
        if (terminal) terminal.textContent = `[+] Attached to process task ${jobId}...\n[*] Streaming real-time tool stdout/stderr...\n\n`;

        if (this.state.pollInterval) clearInterval(this.state.pollInterval);

        this.state.pollInterval = setInterval(async () => {
            const res = await this.apiCall(`/api/scan/status/${jobId}`);
            if (!res.success) {
                clearInterval(this.state.pollInterval);
                return;
            }

            const data = res.data;
            if (terminal) {
                const fullText = (data.stdout || '') + (data.stderr ? `\n[STDERR]\n${data.stderr}` : '');
                terminal.textContent = fullText || `[*] Scan in progress (${data.duration_seconds}s elapsed)...`;
                terminal.scrollTop = terminal.scrollHeight;
            }

            if (['completed', 'failed', 'cancelled', 'timed_out'].includes(data.status)) {
                clearInterval(this.state.pollInterval);
                if (activeBadge) activeBadge.style.display = 'none';

                if (data.status === 'completed') {
                    this.showToast(`Scan completed successfully in ${data.duration_seconds}s!`, "success");
                    // Refresh XP if awarded
                    this.refreshUserStats();
                } else if (data.status === 'cancelled') {
                    this.showToast("Scan was terminated by operator.", "warning");
                } else {
                    this.showToast(`Scan terminated with status: ${data.status}`, "error");
                }
            }
        }, 1500);
    },

    cancelActiveScan: async function() {
        if (!this.state.activeJobId) {
            this.showToast("No active scan currently running.", "info");
            return;
        }

        const res = await this.apiCall(`/api/scan/cancel/${this.state.activeJobId}`, { method: 'POST' });
        if (res.success) {
            this.showToast("Cancellation signal sent.", "warning");
        } else {
            this.showToast(res.error || "Failed to cancel scan.", "error");
        }
    },

    refreshUserStats: async function() {
        const res = await this.apiCall('/api/user/stats');
        if (res.success) {
            const user = res.user;
            const userLevel = document.getElementById('userLevel');
            const barLevel = document.getElementById('barLevel');
            const userXpText = document.getElementById('userXpText');
            const xpBarFill = document.getElementById('xpBarFill');

            if (userLevel) userLevel.textContent = user.level;
            if (barLevel) barLevel.textContent = user.level;
            if (userXpText) userXpText.textContent = `${user.xp_points} XP`;
            if (xpBarFill) xpBarFill.style.width = `${user.xp_points % 100}%`;
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ReconQuest.init();
});
