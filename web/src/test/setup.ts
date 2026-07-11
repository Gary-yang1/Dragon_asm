import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll } from 'vitest';

import { server } from './server';

const originalGetComputedStyle = window.getComputedStyle.bind(window);
window.getComputedStyle = (element: Element) => originalGetComputedStyle(element);

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false
  })
});

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(async () => {
  await new Promise((resolve) => {
    window.setTimeout(resolve, 420);
  });
  server.resetHandlers();
  localStorage.clear();
});
afterAll(() => server.close());
