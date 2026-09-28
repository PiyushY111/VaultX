/** The only error parseCsv throws: the text isn't well-formed CSV. */
export class CsvFormatError extends Error {
  override name = 'CsvFormatError';
}

/**
 * RFC 4180 CSV: comma-separated, fields optionally in double quotes, with ""
 * for a literal quote; quoted fields may contain commas and line breaks.
 * Accepts CRLF or LF line endings and a leading byte-order mark, which is
 * what password managers' exports use.
 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;

  const endField = () => {
    row.push(field);
    field = '';
  };
  const endRow = () => {
    endField();
    // Skip blank lines (a lone empty field), such as a trailing newline.
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
  };

  for (; i < text.length; i++) {
    const char = text[i]!;
    if (quoted) {
      if (char !== '"') field += char;
      else if (text[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (char === '"' && field === '') quoted = true;
    else if (char === ',') endField();
    else if (char === '\n') endRow();
    else if (char === '\r') {
      if (text[i + 1] === '\n') i++;
      endRow();
    } else field += char;
  }
  if (quoted) throw new CsvFormatError('The file ends inside a quoted field; it may be cut off.');
  if (field !== '' || row.length > 0) endRow();
  return rows;
}
