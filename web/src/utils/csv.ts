export function parseCSV(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = '';
  let quoted = false;

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];
    if (quoted) {
      if (char === '"' && input[i + 1] === '"') {
        value += '"';
        i += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        value += char;
      }
      continue;
    }
    if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(value.trim());
      value = '';
    } else if (char === '\n') {
      row.push(value.trim());
      if (row.some((cell) => cell !== '')) rows.push(row);
      row = [];
      value = '';
    } else if (char !== '\r') {
      value += char;
    }
  }
  if (quoted) throw new Error('CSV 包含未闭合的引号');
  row.push(value.trim());
  if (row.some((cell) => cell !== '')) rows.push(row);
  return rows;
}

// Leading characters a spreadsheet treats as the start of a formula. Exported
// rows carry scan-derived text (asset keys, server-side error strings) that an
// external target controls, so a cell can arrive as "=HYPERLINK(...)" and execute
// when the analyst opens the file (CWE-1236).
const formulaPrefixes = '=+-@\t\r';

export function serializeCSV(rows: Array<Array<string | number | undefined>>) {
  return rows
    .map((row) => row.map((value) => {
      // Numbers are formatted as-is so a negative value stays machine-readable;
      // only text is prefixed.
      const isText = typeof value !== 'number';
      let text = String(value ?? '');
      if (isText && text !== '' && formulaPrefixes.includes(text[0])) {
        text = `'${text}`;
      }
      return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
    }).join(','))
    .join('\r\n');
}
