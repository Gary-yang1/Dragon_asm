import { describe, expect, it } from 'vitest';

import { sanitizeDisplayName } from './text';

describe('sanitizeDisplayName', () => {
  it('removes invisible and control characters', () => {
    expect(sanitizeDisplayName('A\u200B\u0007lice')).toBe('Alice');
    expect(sanitizeDisplayName('\u2060John\u00AD Doe')).toBe('John Doe');
  });

  it('restores URL-encoded content', () => {
    expect(sanitizeDisplayName('%E6%B5%8B%E8%AF%95')).toBe('测试');
  });

  it('fixes latin1-like UTF-8 bytes', () => {
    expect(sanitizeDisplayName('\u00e6\u00b5\u008b\u00e8\u00af\u0095')).toBe('测试');
  });

  it('fixes cp1252-like UTF-8 bytes', () => {
    expect(sanitizeDisplayName('\u00e6\u00b5\u2039\u00e8\u00af\u2022\u00e7\u00ae\u00a1\u00e7\u0090\u2020\u00e5\u2018\u02dc')).toBe('测试管理员');
  });
});
