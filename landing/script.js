/**
 * VaultX Minimal Landing Page Scripts
 * 1-Click Copy, Setup Tab Switcher, Smooth In-Page Nav
 */

document.addEventListener('DOMContentLoaded', () => {
  initCopyButtons();
  initSetupTabs();
});

/* 1-Click Copy */
function initCopyButtons() {
  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const textToCopy = btn.getAttribute('data-copy');
      if (!textToCopy) return;

      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalText = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = 'Copied!';
        showToast('Command copied to clipboard');

        setTimeout(() => {
          btn.classList.remove('copied');
          btn.innerHTML = originalText;
        }, 2000);
      } catch {
        showToast('Failed to copy, please select manually');
      }
    });
  });
}

function showToast(message) {
  const container = document.getElementById('toastBox');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast-msg';
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast);
  }, 2400);
}

/* Setup Tabs Switcher */
function initSetupTabs() {
  const triggers = document.querySelectorAll('.tab-trigger');
  const panes = document.querySelectorAll('.tab-content');

  triggers.forEach((trigger) => {
    trigger.addEventListener('click', () => {
      const targetId = trigger.getAttribute('data-tab');

      triggers.forEach((t) => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
      });

      panes.forEach((p) => {
        p.classList.remove('active');
        p.setAttribute('hidden', '');
      });

      trigger.classList.add('active');
      trigger.setAttribute('aria-selected', 'true');

      const activePane = document.getElementById(targetId);
      if (activePane) {
        activePane.classList.add('active');
        activePane.removeAttribute('hidden');
      }
    });
  });
}
