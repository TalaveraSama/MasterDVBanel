/* Preferencia visual local: no modifica ajustes del servidor ni de otros usuarios. */
(() => {
  'use strict';

  const STORAGE_KEY = 'tbs-webui-theme';
  const DEFAULT_THEME = 'original';
  const THEMES = new Set(['original', 'aurora', 'cesbo']);

  function readTheme() {
    try {
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved && THEMES.has(saved)) return saved;
    } catch (_) {
      // El navegador puede bloquear localStorage; se conserva el tema por defecto.
    }
    const current = document.documentElement.dataset.theme;
    return THEMES.has(current) ? current : DEFAULT_THEME;
  }

  function applyTheme(theme, persist = true) {
    const selected = THEMES.has(theme) ? theme : DEFAULT_THEME;
    document.documentElement.dataset.theme = selected;
    if (persist) {
      try {
        window.localStorage.setItem(STORAGE_KEY, selected);
      } catch (_) {
        // El tema sigue aplicado en esta página aunque no se pueda guardar.
      }
    }
    return selected;
  }

  // Se ejecuta en el head, antes de cargar las hojas de estilo, para evitar flash.
  const initialTheme = applyTheme(readTheme(), false);

  function bindSelector() {
    const selector = document.getElementById('theme-select');
    if (!selector) return;
    selector.value = initialTheme;
    selector.addEventListener('change', () => applyTheme(selector.value));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindSelector, { once: true });
  } else {
    bindSelector();
  }
})();
