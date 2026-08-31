import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../../hooks', () => ({
  useClipboard: () => ({ copy: vi.fn() }),
}))

vi.mock('../../../components/ui/ToggleSwitch', () => ({
  ToggleSwitch: () => null,
}))

vi.mock('../../../components', () => ({
  HelpCard: ({ children }) => <div>{children}</div>,
  Button: ({ children, ...props }) => <button {...props}>{children}</button>,
  Badge: ({ children }) => <span>{children}</span>,
  CompactSection: ({ title, children }) => <section><h2>{title}</h2>{children}</section>,
  Select: () => null,
  Input: (props) => <input {...props} />,
  FilterSelect: ({ value, onChange, allLabel, options }) => (
    <select aria-label="status-filter" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{allLabel}</option>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  ),
}))

import LetsEncryptTab from '../LetsEncryptTab'

const orders = [
  { id: 1, primary_domain: 'a.example.com', status: 'valid', environment: 'production' },
  { id: 2, primary_domain: 'b.example.com', status: 'pending', environment: 'production' },
]

const noop = vi.fn()
const renderTab = (props = {}) => render(
  <LetsEncryptTab
    clientOrders={orders}
    selectedClientOrder={null}
    onSelectOrder={noop}
    clientSettings={{}}
    localContactEmail=""
    onLocalContactEmailChange={noop}
    localProxyUpstreamUrl=""
    onLocalProxyUpstreamUrlChange={noop}
    localProxyEabKid=""
    onLocalProxyEabKidChange={noop}
    proxyEabHmacInput=""
    onProxyEabHmacInputChange={noop}
    proxyEmail=""
    onProxyEmailChange={noop}
    testingConnection={false}
    connectionResult={null}
    onBlurSave={noop}
    onBlurSaveInt={noop}
    localDnsTimeout="120"
    onLocalDnsTimeoutChange={noop}
    onUpdateClientSetting={noop}
    onRegisterProxy={noop}
    onUnregisterProxy={noop}
    onProxyAccountChange={noop}
    onResetProxyAccount={noop}
    onTestConnection={noop}
    onRequestCertificate={noop}
    onRefresh={noop}
    onCheckOrderStatus={noop}
    onVerifyChallenge={noop}
    onFinalizeOrder={noop}
    onViewCertificate={noop}
    onDownloadCertificate={noop}
    onRenewCertificate={noop}
    onDeleteOrder={noop}
    canWrite
    canDelete
    {...props}
  />
)

describe('LetsEncryptTab orders filter (#303 follow-up)', () => {
  beforeEach(() => vi.clearAllMocks())

  it('titles the section with the visible/total count', () => {
    renderTab()
    expect(screen.getByText('acme.letsEncryptOrders (2/2)')).toBeInTheDocument()
    expect(screen.getByText('a.example.com')).toBeInTheDocument()
    expect(screen.getByText('b.example.com')).toBeInTheDocument()
  })

  it('filters the list by status', () => {
    renderTab()
    fireEvent.change(screen.getByLabelText('status-filter'), { target: { value: 'valid' } })
    expect(screen.getByText('acme.letsEncryptOrders (1/2)')).toBeInTheDocument()
    expect(screen.getByText('a.example.com')).toBeInTheDocument()
    expect(screen.queryByText('b.example.com')).not.toBeInTheDocument()
  })

  it('shows a no-results state when the filter matches nothing', () => {
    renderTab()
    fireEvent.change(screen.getByLabelText('status-filter'), { target: { value: 'invalid' } })
    expect(screen.getByText('acme.letsEncryptOrders (0/2)')).toBeInTheDocument()
    expect(screen.getByText('common.noResults')).toBeInTheDocument()
  })
})
