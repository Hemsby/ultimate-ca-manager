import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  patch: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
  hasPermission: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../../services', () => ({
  apiClient: { patch: mocks.patch },
}))

vi.mock('../../../contexts', () => ({
  useNotification: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }),
}))

vi.mock('../../../hooks', () => ({
  useClipboard: () => ({ copy: vi.fn() }),
  usePermission: () => ({ hasPermission: mocks.hasPermission }),
}))

vi.mock('../../../components', async () => {
  // Real Compact* components: a mock rendering children would hide the fact
  // that CompactField only renders its `value`/`children` contract
  const detailCard = await vi.importActual('../../../components/DetailCard.jsx')
  return {
    Badge: ({ children }) => <span>{children}</span>,
    Button: ({ children, ...props }) => <button {...props}>{children}</button>,
    Input: ({ value, onChange, helperText, ...props }) => (
      <>
        <input aria-label="email-draft" value={value} onChange={onChange} {...props} />
        {helperText && <span>{helperText}</span>}
      </>
    ),
    StatusIndicator: ({ children }) => <span>{children}</span>,
    CompactSection: detailCard.CompactSection,
    CompactGrid: detailCard.CompactGrid,
    CompactField: detailCard.CompactField,
    CompactStats: detailCard.CompactStats,
    CompactHeader: detailCard.CompactHeader,
  }
})

import AccountDetailPanel from '../AccountDetailPanel'

const account = {
  id: 7,
  account_id: 'acme-1234567890abcdef',
  status: 'valid',
  contact: ['mailto:old@example.com'],
  key_type: 'EC-P256',
  created_at: '2026-01-01T00:00:00Z',
}

const renderPanel = (props = {}) => render(
  <AccountDetailPanel
    account={account}
    orders={[]}
    challenges={[]}
    detailTabs={[]}
    activeDetailTab="account"
    onDetailTabChange={vi.fn()}
    onDeactivate={vi.fn()}
    onDelete={vi.fn()}
    {...props}
  />
)

describe('AccountDetailPanel email edit', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.hasPermission.mockReturnValue(true)
  })

  it('renders the current email in the account information grid', () => {
    renderPanel()
    // once in the panel header, once in the account information grid
    expect(screen.getAllByText('old@example.com').length).toBeGreaterThanOrEqual(2)
  })

  it('saves the new email through the API and notifies the parent', async () => {
    mocks.patch.mockResolvedValue({})
    const onChanged = vi.fn()
    renderPanel({ onChanged })

    fireEvent.click(screen.getByLabelText('acme.editEmail'))
    fireEvent.change(screen.getByLabelText('email-draft'), { target: { value: 'new@example.com' } })
    fireEvent.click(screen.getByText('common.save'))

    await vi.waitFor(() => expect(mocks.patch).toHaveBeenCalledWith(
      '/acme/accounts/acme-1234567890abcdef', { email: 'new@example.com' }
    ))
    expect(onChanged).toHaveBeenCalled()
    expect(mocks.showSuccess).toHaveBeenCalled()
  })

  it('hides the edit button without write:acme', () => {
    mocks.hasPermission.mockImplementation((p) => p !== 'write:acme')
    renderPanel()
    expect(screen.queryByLabelText('acme.editEmail')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('email-draft')).not.toBeInTheDocument()
  })

  it('shows the RFC 8555 caveat while editing', () => {
    renderPanel()
    fireEvent.click(screen.getByLabelText('acme.editEmail'))
    expect(screen.getByText('acme.editEmailCaveat')).toBeInTheDocument()
  })
})
