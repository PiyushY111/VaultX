import { describe, expect, it } from 'vitest';
import { parseCsv } from './csv';

describe('parseCsv', () => {
  it('splits rows and fields', () => {
    expect(parseCsv('a,b,c\n1,2,3\n')).toEqual([
      ['a', 'b', 'c'],
      ['1', '2', '3'],
    ]);
  });

  it('handles quotes, escaped quotes, commas and line breaks inside quotes', () => {
    expect(parseCsv('name,notes\r\n"x, y","say ""hi""\nline 2"\r\n')).toEqual([
      ['name', 'notes'],
      ['x, y', 'say "hi"\nline 2'],
    ]);
  });

  it('keeps empty fields, skips blank lines, and ignores a byte-order mark', () => {
    expect(parseCsv('﻿a,,c\n\n,,\n')).toEqual([
      ['a', '', 'c'],
      ['', '', ''],
    ]);
  });

  it('keeps spaces (passwords can have them)', () => {
    expect(parseCsv('p\n  two spaces  \n')).toEqual([['p'], ['  two spaces  ']]);
  });

  it('refuses a file cut off inside a quoted field', () => {
    expect(() => parseCsv('a\n"unfinished')).toThrow(/cut off/);
  });
});
