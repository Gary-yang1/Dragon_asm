import { describe, expect, it } from 'vitest';

import { parseCSV, serializeCSV } from './csv';

describe('CSV utilities', () => {
  it('parses quoted commas, escaped quotes and CRLF', () => {
    expect(parseCSV('asset_type,value,display_name\r\ndomain,example.com,"Main, ""Public"""')).toEqual([
      ['asset_type', 'value', 'display_name'],
      ['domain', 'example.com', 'Main, "Public"']
    ]);
  });

  it('rejects an unterminated quoted value', () => {
    expect(() => parseCSV('domain,example.com,"broken')).toThrow('未闭合');
  });

  it('serializes values that require quoting', () => {
    expect(serializeCSV([['value', 'error'], ['example.com', 'bad, "value"']])).toBe('value,error\r\nexample.com,"bad, ""value"""');
  });

  // Exported rows carry server-derived strings (asset keys, per-row error text)
  // originating from scanned third-party infrastructure, so a cell can begin with
  // a formula character and execute when opened in a spreadsheet (CWE-1236).
  it('neutralises spreadsheet formula injection in text cells', () => {
    const csv = serializeCSV([
      ['asset_key', 'error'],
      ['=HYPERLINK("http://evil.test","click")', '+cmd|calc'],
      ['@SUM(A1)', '-2+3'],
      ['domain:example.com', '']
    ]);

    for (const row of parseCSV(csv).slice(1)) {
      for (const cell of row) {
        if (cell === '') continue;
        expect('=+-@\t\r'.includes(cell[0])).toBe(false);
      }
    }
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).toContain("'+cmd|calc");
  });

  it('leaves numbers machine-readable', () => {
    const csv = serializeCSV([['confidence'], [90], [-3]]);
    expect(csv).toContain('90');
    // A negative number must not be quoted into text.
    expect(csv).toContain('-3');
    expect(csv).not.toContain("'-3");
  });
});
