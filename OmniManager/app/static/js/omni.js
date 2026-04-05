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

  function updateToggleIcon(collapsed) {
    if (!toggleBtn) return;
    const icon = toggleBtn.querySelector('i');
    if (icon) {
      icon.className = collapsed ? 'bi bi-layout-sidebar-reverse' : 'bi bi-layout-sidebar';
    }
    toggleBtn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
  }

  function updateNavTooltips(collapsed) {
    document.querySelectorAll('.omni-nav-link').forEach(link => {
      // Dispose any existing tooltip first
      const existing = bootstrap.Tooltip.getInstance(link);
      if (existing) existing.dispose();

      if (collapsed) {
        const label = link.querySelector('span');
        if (label) {
          link.setAttribute('data-bs-toggle', 'tooltip');
          link.setAttribute('data-bs-placement', 'right');
          link.setAttribute('title', label.textContent.trim());
          new bootstrap.Tooltip(link, { trigger: 'hover', placement: 'right' });
        }
      } else {
        link.removeAttribute('data-bs-toggle');
        link.removeAttribute('title');
      }
    });
  }

  function setCollapsed(collapsed) {
    sidebar.classList.toggle('collapsed', collapsed);
    main.classList.toggle('expanded', collapsed);
    localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
    updateToggleIcon(collapsed);
    updateNavTooltips(collapsed);
  }

  // Restore saved state
  const isCollapsed = localStorage.getItem(COLLAPSED_KEY) === '1';
  setCollapsed(isCollapsed);

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

// ── Dark / light mode toggle ──────────────────────────────────────────────────

function initThemeToggle() {
  const root = document.getElementById('htmlRoot');
  const toggleBtn = document.getElementById('themeToggle');
  const icon = document.getElementById('themeIcon');
  if (!root || !toggleBtn) return;

  const THEME_KEY = 'omni_theme';

  function applyTheme(theme) {
    root.setAttribute('data-bs-theme', theme);
    if (icon) {
      icon.className = theme === 'dark' ? 'bi bi-moon-stars-fill' : 'bi bi-sun-fill';
    }
    localStorage.setItem(THEME_KEY, theme);
  }

  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(saved);

  toggleBtn.addEventListener('click', () => {
    const current = root.getAttribute('data-bs-theme');
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
}

// ── Notification bell ─────────────────────────────────────────────────────────

function initNotifications() {
  const badge = document.getElementById('notifBadge');
  const itemsEl = document.getElementById('notifItems');
  const markBtn = document.getElementById('markAllRead');
  const dropdown = document.getElementById('notifDropdown');
  if (!badge || !itemsEl) return;

  async function fetchNotifs() {
    try {
      const resp = await fetch('/notifications/unread-count');
      if (!resp.ok) return;
      const data = await resp.json();
      // Update badge
      if (data.count > 0) {
        badge.textContent = data.count > 99 ? '99+' : data.count;
        badge.classList.remove('d-none');
      } else {
        badge.classList.add('d-none');
      }
      // Populate dropdown
      if (data.recent && data.recent.length) {
        itemsEl.innerHTML = data.recent.map(n => `
          <li>
            <a class="dropdown-item px-3 py-2 d-flex gap-2 align-items-start ${n.read ? '' : 'fw-semibold'}"
               href="${n.link || '#'}">
              <i class="bi ${iconForType(n.type)} mt-1 flex-shrink-0"></i>
              <div>
                <div class="small">${escHtml(n.title)}</div>
                ${n.message ? `<div class="text-muted" style="font-size:0.75rem">${escHtml(n.message)}</div>` : ''}
                <div class="text-muted" style="font-size:0.7rem">${n.created_at}</div>
              </div>
            </a>
          </li>`).join('');
      } else {
        itemsEl.innerHTML = '<li class="px-3 py-2 text-muted small">No recent notifications</li>';
      }
    } catch (_) {}
  }

  function iconForType(t) {
    return { success: 'bi-check-circle-fill text-success', warning: 'bi-exclamation-triangle-fill text-warning',
             danger: 'bi-x-circle-fill text-danger', info: 'bi-info-circle-fill text-info' }[t] || 'bi-bell-fill';
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Load on dropdown open
  if (dropdown) {
    dropdown.addEventListener('show.bs.dropdown', fetchNotifs);
  }

  // Poll every 30s
  fetchNotifs();
  setInterval(fetchNotifs, 30000);

  if (markBtn) {
    markBtn.addEventListener('click', async () => {
      await fetch('/notifications/mark-read', {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken() },
      });
      badge.classList.add('d-none');
      itemsEl.innerHTML = '<li class="px-3 py-2 text-muted small">No recent notifications</li>';
    });
  }
}

// ── Dashboard live refresh ────────────────────────────────────────────────────

function initDashboardRefresh() {
  const kpiMap = {
    'kpi-total-endpoints': 'total_endpoints',
    'kpi-online': 'online',
    'kpi-offline': 'offline',
    'kpi-unknown': 'unknown',
    'kpi-missing-patches': 'missing_patches',
    'kpi-critical-patches': 'critical_patches',
    'kpi-total-vulns': 'total_vulns',
    'kpi-critical-vulns': 'critical_vulns',
  };

  const hasDashboardKPIs = Object.keys(kpiMap).some(id => document.getElementById(id));
  if (!hasDashboardKPIs) return;

  async function refreshKPIs() {
    try {
      const resp = await fetch('/api/kpis');
      if (!resp.ok) return;
      const data = await resp.json();
      for (const [id, key] of Object.entries(kpiMap)) {
        const el = document.getElementById(id);
        if (el && data[key] !== undefined) el.textContent = data[key];
      }
    } catch (_) {}
  }

  setInterval(refreshKPIs, 30000);
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initAlerts();
  initConfirm();
  initRowLinks();
  initPingButtons();
  initCopyButtons();
  initThemeToggle();
  initNotifications();
  initDashboardRefresh();

  // Activate Bootstrap tooltips (skip nav links — managed by initSidebar)
  document.querySelectorAll('[title]:not(.omni-nav-link)').forEach(el => {
    new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
  });

  // Activate Bootstrap popovers
  document.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => {
    new bootstrap.Popover(el);
  });
});
