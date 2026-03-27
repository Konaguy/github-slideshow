/* ═══════════════════════════════════════════════════════════════════
   OmniManager — Client-side JS
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

// ── CSRF helper ───────────────────────────────────────────────────────────────

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.getAttribute('content');
  // Fallback: read from any hidden CSRF input on the page
  const input = document.querySelector('input[name="csrf_token"]');
  return input ? input.value : '';
}

// ── Toast notifications ───────────────────────────────────────────────────────

let toastContainer = null;

function getToastContainer() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toastContainer';
    document.body.appendChild(toastContainer);
  }
  return toastContainer;
}

function showToast(message, type = 'info', duration = 4000) {
  const container = getToastContainer();
  const toast = document.createElement('div');
  toast.className = `omni-toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(2rem)';
    toast.style.transition = 'opacity 0.3s, transform 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Sidebar collapse ──────────────────────────────────────────────────────────

function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('main');
  const toggleBtn = document.getElementById('sidebarToggle');
  const mobileToggle = document.getElementById('mobileSidebarToggle');

  if (!sidebar) return;

  const COLLAPSED_KEY = 'omni_sidebar_collapsed';

  function setCollapsed(collapsed) {
    sidebar.classList.toggle('collapsed', collapsed);
    main.classList.toggle('expanded', collapsed);
    localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
  }

  // Restore state
  if (localStorage.getItem(COLLAPSED_KEY) === '1') {
    setCollapsed(true);
  }

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      setCollapsed(!sidebar.classList.contains('collapsed'));
    });
  }

  // Mobile toggle
  if (mobileToggle) {
    mobileToggle.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (
        window.innerWidth <= 768 &&
        sidebar.classList.contains('mobile-open') &&
        !sidebar.contains(e.target) &&
        e.target !== mobileToggle
      ) {
        sidebar.classList.remove('mobile-open');
      }
    });
  }
}

// ── Auto-dismiss alerts ───────────────────────────────────────────────────────

function initAlerts() {
  document.querySelectorAll('.alert:not(.alert-danger)').forEach(alert => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      bsAlert.close();
    }, 5000);
  });
}

// ── Confirm on data-confirm elements ─────────────────────────────────────────

function initConfirm() {
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', function (e) {
      if (!confirm(this.dataset.confirm)) {
        e.preventDefault();
        e.stopPropagation();
      }
    });
  });
}

// ── Table row click → link ────────────────────────────────────────────────────

function initRowLinks() {
  document.querySelectorAll('tr[data-href]').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
      window.location.href = row.dataset.href;
    });
  });
}

// ── Live ping (generic) ───────────────────────────────────────────────────────

function initPingButtons() {
  document.querySelectorAll('.ping-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
      const id = this.dataset.endpointId;
      if (!id) return;
      this.disabled = true;
      const original = this.innerHTML;
      this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      try {
        const resp = await fetch(`/endpoints/${id}/ping`, {
          method: 'POST',
          headers: { 'X-CSRFToken': getCsrfToken() },
        });
        const data = await resp.json();
        const type = data.status === 'online' ? 'success' : 'danger';
        showToast(`${this.dataset.hostname || 'Endpoint'}: ${data.status}`, type);
      } catch (err) {
        showToast('Ping failed: ' + err.message, 'danger');
      } finally {
        this.disabled = false;
        this.innerHTML = original;
      }
    });
  });
}

// ── SocketIO room join helper ─────────────────────────────────────────────────
// Pages that use SocketIO emit 'join' with a room name on connect.
// This helper can be called from page-specific scripts.

function joinRoom(socket, room) {
  socket.emit('join', { room });
  socket.on('connect', () => socket.emit('join', { room }));
}

// ── Clipboard copy ────────────────────────────────────────────────────────────

function initCopyButtons() {
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(this.dataset.copy).then(() => {
        const original = this.textContent;
        this.textContent = 'Copied!';
        setTimeout(() => (this.textContent = original), 1500);
      });
    });
  });
}

// ── Fetch wrapper with CSRF ───────────────────────────────────────────────────

async function omniPost(url, body = {}) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || resp.statusText);
  }
  return resp.json();
}

// ── Format dates relative ─────────────────────────────────────────────────────

function relativeTime(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initAlerts();
  initConfirm();
  initRowLinks();
  initPingButtons();
  initCopyButtons();

  // Activate Bootstrap tooltips
  document.querySelectorAll('[title]').forEach(el => {
    new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
  });

  // Activate Bootstrap popovers
  document.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => {
    new bootstrap.Popover(el);
  });
});
