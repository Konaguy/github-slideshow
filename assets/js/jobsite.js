// CyberTalent Job Site — Global JS helpers
// Modal and toast utilities are defined in the layout (jobsite.html)
// This file contains shared page-level logic

document.addEventListener('DOMContentLoaded', function () {
  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // Highlight active nav link based on current page
  const path = window.location.pathname;
  document.querySelectorAll('nav a').forEach(link => {
    if (link.getAttribute('href') && path.includes(link.getAttribute('href').replace('/', ''))) {
      link.classList.add('text-cyber-400');
      link.classList.remove('text-slate-300');
    }
  });

  // Keyboard shortcut: press '/' to focus search input on listings page
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      const searchInput = document.getElementById('searchInput');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
      }
    }
  });
});
