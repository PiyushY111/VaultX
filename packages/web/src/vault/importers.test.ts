import { describe, expect, it } from 'vitest';
import { parseImport, withoutDuplicates } from './importers';

// Header rows exactly as each app writes them.
const CHROME = `name,url,username,password,note
github.com,https://github.com/login,octocat,gh-pass,work
accounts.google.com,https://accounts.google.com/signin/v2,alice@gmail.com,"p,w ""q""",
`;

const FIREFOX = `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timePasswordChanged","timeLastUsed"
"https://www.reddit.com","redditor","rd-pass",,"https://www.reddit.com","{a}","1","1","1"
`;

const BITWARDEN = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,GitLab,"multi
line",,0,https://gitlab.com/users/sign_in,gl-user,gl-pass,otpauth://totp/GitLab?secret=ABC
,,note,My secret note,just a note,,0,,,,
,,card,Visa,,,0,,,,
`;

const ONEPASSWORD = `"Title","Url","Username","Password","OTPAuth","Favorite","Archived","Tags","Notes"
"Amazon","https://www.amazon.com/ap/signin","shopper","amz-pass","","false","false","","gift cards"
"Wi-Fi","","","wifi-pass","","false","false","",""
`;

describe('parseImport', () => {
  it('reads a Chrome export (also Edge and Brave)', () => {
    const result = parseImport(CHROME);
    expect(result.source).toBe('Chrome');
    expect(result.items).toEqual([
      { site: 'github.com', username: 'octocat', password: 'gh-pass', notes: 'work' },
      {
        site: 'accounts.google.com',
        username: 'alice@gmail.com',
        password: 'p,w "q"',
        notes: '',
      },
    ]);
  });

  it('reads a Firefox export', () => {
    const result = parseImport(FIREFOX);
    expect(result.source).toBe('Firefox');
    expect(result.items).toEqual([
      { site: 'reddit.com', username: 'redditor', password: 'rd-pass', notes: '' },
    ]);
  });

  it('reads a Bitwarden export, keeping TOTP secrets in notes and skipping non-logins', () => {
    const result = parseImport(BITWARDEN);
    expect(result.source).toBe('Bitwarden');
    expect(result.skipped).toBe(2);
    expect(result.items).toEqual([
      {
        site: 'gitlab.com',
        username: 'gl-user',
        password: 'gl-pass',
        notes: 'multi\nline\nName: GitLab\nTOTP: otpauth://totp/GitLab?secret=ABC',
      },
    ]);
  });

  it('puts valid two-factor secrets in their own field', () => {
    const csv = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,GitHub,,,0,https://github.com,octocat,gh-pass,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP
`;
    expect(parseImport(csv).items).toEqual([
      {
        site: 'github.com',
        username: 'octocat',
        password: 'gh-pass',
        notes: 'Name: GitHub',
        totp: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP',
      },
    ]);
  });

  it('reads a 1Password export, using the title when there is no URL', () => {
    const result = parseImport(ONEPASSWORD);
    expect(result.source).toBe('1Password');
    expect(result.items).toEqual([
      {
        site: 'amazon.com',
        username: 'shopper',
        password: 'amz-pass',
        notes: 'gift cards\nName: Amazon',
      },
      { site: 'Wi-Fi', username: '', password: 'wifi-pass', notes: '' },
    ]);
  });

  it('refuses files that are not password exports', () => {
    expect(() => parseImport('')).toThrow(/empty/);
    expect(() => parseImport('a,b\n1,2\n')).toThrow(/password column/);
  });
});

describe('withoutDuplicates', () => {
  it('drops logins already in the vault and repeats in the file', () => {
    const existing = [{ site: 'GitHub.com', username: 'u', password: 'p', notes: 'x' }];
    const incoming = [
      { site: 'github.com', username: 'u', password: 'p', notes: '' },
      { site: 'github.com', username: 'u', password: 'NEW', notes: '' },
      { site: 'github.com', username: 'u', password: 'NEW', notes: '' },
    ];
    expect(withoutDuplicates(incoming, existing)).toEqual({
      items: [{ site: 'github.com', username: 'u', password: 'NEW', notes: '' }],
      duplicates: 2,
    });
  });
});
