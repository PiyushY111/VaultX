import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { VaultItemData } from '../vault/items';
import { ItemForm } from './ItemForm';

describe('ItemForm', () => {
  it('keeps fields from newer versions when an item is edited and saved', async () => {
    const initial: VaultItemData = {
      site: 'github.com',
      username: 'octocat',
      password: 'pw',
      notes: '',
      extra: { futureLabel: 'Work', futureDate: '2026-10-01T00:00:00.000Z' },
    };
    const onSave = vi.fn<(data: VaultItemData) => Promise<void>>(async () => {});
    render(<ItemForm initial={initial} isNew={false} onSave={onSave} onCancel={() => {}} />);

    const notes = screen.getByLabelText(/notes/i);
    await userEvent.type(notes, 'edited');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave.mock.calls[0]![0]).toMatchObject({ notes: 'edited', extra: initial.extra });
  });

  const login: VaultItemData = {
    site: 'shop.example.com',
    username: 'me',
    password: 'pw',
    notes: '',
  };

  it('saves how a login matches pages, explaining each choice', async () => {
    const onSave = vi.fn<(data: VaultItemData) => Promise<void>>(async () => {});
    render(<ItemForm initial={login} isNew={false} onSave={onSave} onCancel={() => {}} />);
    await userEvent.click(screen.getByText('Advanced'));
    const select = screen.getByLabelText('Fill on');
    expect(select).toHaveValue('host');
    await userEvent.selectOptions(select, 'domain');
    expect(screen.getByText(/also filled on example.com/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave.mock.calls[0]![0]).toMatchObject({ match: 'domain' });
  });

  it('warns that a login saved for a public suffix will never be filled', async () => {
    render(
      <ItemForm
        initial={{ ...login, site: 'co.uk' }}
        isNew={false}
        onSave={vi.fn()}
        onCancel={() => {}}
      />,
    );
    expect(await screen.findByRole('status')).toHaveTextContent(
      /won’t fill this login anywhere: “co.uk”.*login.example.co.uk/,
    );
    await userEvent.clear(screen.getByLabelText('Site'));
    await userEvent.type(screen.getByLabelText('Site'), 'bbc.co.uk');
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
  });
});
