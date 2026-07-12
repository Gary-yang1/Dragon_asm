import { create } from 'zustand';

export type ThemeMode = 'light' | 'dark';

interface ThemeState {
  mode: ThemeMode;
  toggleMode: () => void;
}

function getInitialMode(): ThemeMode {
  const stored = localStorage.getItem('asm.theme');
  if (stored === 'light' || stored === 'dark') return stored;
  if (typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  return 'dark';
}

function applyTheme(mode: ThemeMode) {
  document.documentElement.setAttribute('data-theme', mode);
  localStorage.setItem('asm.theme', mode);
}

export const useThemeStore = create<ThemeState>((set) => {
  const initial = getInitialMode();
  applyTheme(initial);
  return {
    mode: initial,
    toggleMode: () =>
      set((state) => {
        const next = state.mode === 'dark' ? 'light' : 'dark';
        applyTheme(next);
        return { mode: next };
      })
  };
});
