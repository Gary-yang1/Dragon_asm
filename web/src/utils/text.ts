export function sanitizeDisplayName(raw: string): string {
  const forbiddenChars = new Set([
    '\u200B',
    '\u200C',
    '\u200D',
    '\uFEFF',
    '\u200E',
    '\u200F',
    '\u202A',
    '\u202B',
    '\u202C',
    '\u202D',
    '\u202E',
    '\u2060',
    '\u00AD'
  ]);

  const withoutInvisible = [...raw].filter((char) => !forbiddenChars.has(char)).join('');
  let normalized = withoutInvisible.trim();
  if (!normalized) return '';

  const safeDecode = (value: string) => {
    let current = value;
    for (let i = 0; i < 2; i += 1) {
      if (!current.includes('%')) break;
      try {
        current = decodeURIComponent(current);
      } catch {
        break;
      }
    }
    return current;
  };

  const cp1252Bytes = new Map<string, number>([
    ['\u20AC', 0x80],
    ['\u201A', 0x82],
    ['\u0192', 0x83],
    ['\u201E', 0x84],
    ['\u2026', 0x85],
    ['\u2020', 0x86],
    ['\u2021', 0x87],
    ['\u02C6', 0x88],
    ['\u2030', 0x89],
    ['\u0160', 0x8a],
    ['\u2039', 0x8b],
    ['\u0152', 0x8c],
    ['\u017D', 0x8e],
    ['\u2018', 0x91],
    ['\u2019', 0x92],
    ['\u201C', 0x93],
    ['\u201D', 0x94],
    ['\u2022', 0x95],
    ['\u2013', 0x96],
    ['\u2014', 0x97],
    ['\u02DC', 0x98],
    ['\u2122', 0x99],
    ['\u0161', 0x9a],
    ['\u203A', 0x9b],
    ['\u0153', 0x9c],
    ['\u017E', 0x9e],
    ['\u0178', 0x9f]
  ]);

  const tryDecodeUtf8Mojibake = (value: string) => {
    const bytes: number[] = [];
    const canMapToSingleByte = Array.from(value).every((char) => {
      const codePoint = char.codePointAt(0);
      if (codePoint !== undefined && codePoint <= 0xff) {
        bytes.push(codePoint);
        return true;
      }
      const mapped = cp1252Bytes.get(char);
      if (mapped !== undefined) {
        bytes.push(mapped);
        return true;
      }
      return false;
    });
    if (!canMapToSingleByte) return value;
    if (typeof globalThis.TextDecoder !== 'function') return value;
    try {
      const byteArray = new Uint8Array(bytes);
      const decoder = new globalThis.TextDecoder('utf-8');
      const decoded = decoder.decode(byteArray);
      if (!decoded.includes('\uFFFD')) return decoded;
    } catch {
      // ignore decode failures and keep original value
    }
    return value;
  };

  normalized = safeDecode(normalized);
  normalized = tryDecodeUtf8Mojibake(normalized);
  normalized = Array.from(normalized).filter((char) => {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined) return false;
    if (codePoint < 0x20 || codePoint === 0x7f) return false;
    if (codePoint >= 0x80 && codePoint <= 0x9f) return false;
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) return false;
    return true;
  }).join('').trim();
  normalized = normalized.replace(/\uFFFD/g, '');
  return normalized.normalize ? normalized.normalize('NFC') : normalized;
}
