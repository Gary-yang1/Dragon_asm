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
});
