import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EFF_LARGE } from '../lib/wordlist/effLarge';
import { PasswordGenerator } from './PasswordGenerator';

const output = () => screen.getByRole('status', { name: 'Generated password' });
const words = (text: string | null) => (text ?? '').split('-');

beforeEach(() => {
  localStorage.clear();
});

describe('PasswordGenerator', () => {
  it('makes character passwords by default', () => {
    render(<PasswordGenerator />);
    expect(screen.getByRole('button', { name: 'Characters' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(output().textContent).toHaveLength(20);
    expect(screen.getByLabelText(/Length/)).toBeInTheDocument();
  });

  it('switches to a six-word passphrase from the EFF list', async () => {
    const user = userEvent.setup();
    render(<PasswordGenerator />);
    await user.click(screen.getByRole('button', { name: 'Passphrase' }));

    await vi.waitFor(() => expect(words(output().textContent)).toHaveLength(6));
    for (const word of words(output().textContent)) {
      expect(EFF_LARGE).toContain(word.toLowerCase().replace(/[0-9]$/, ''));
    }
    expect(screen.queryByLabelText(/Length/)).not.toBeInTheDocument();
    expect(screen.getByText(/~\d+ bits of entropy/)).toHaveTextContent('~86 bits');
  });

  it('follows the word count and separator, and hands the passphrase to onUse', async () => {
    const user = userEvent.setup();
    const onUse = vi.fn();
    render(<PasswordGenerator onUse={onUse} />);
    await user.click(screen.getByRole('button', { name: 'Passphrase' }));
    await vi.waitFor(() => expect(words(output().textContent)).toHaveLength(6));

    await user.selectOptions(screen.getByLabelText('Separator'), '.');
    await user.click(screen.getByLabelText('Capitalize'));
    await user.click(screen.getByLabelText('Add a number'));
    const passphrase = output().textContent!;
    expect(passphrase.split('.')).toHaveLength(6);
    expect(passphrase).toMatch(/^[a-z.]+$/);

    await user.click(screen.getByRole('button', { name: 'Use this password' }));
    expect(onUse).toHaveBeenCalledWith(passphrase);
  });

  it('remembers passphrase mode for next time', async () => {
    const user = userEvent.setup();
    const { unmount } = render(<PasswordGenerator />);
    await user.click(screen.getByRole('button', { name: 'Passphrase' }));
    unmount();

    render(<PasswordGenerator />);
    expect(screen.getByRole('button', { name: 'Passphrase' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await vi.waitFor(() => expect(words(output().textContent)).toHaveLength(6));
  });
});
