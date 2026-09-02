/**
 * CreateCAModal — Name Constraints (#316): the Advanced Constraints section
 * collects permitted/excluded {type, value} rows, drops blank rows, and hides
 * the fields for an external-CSR CA (the signing CA sets them there).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  getProviders: vi.fn(),
  showSuccess: vi.fn(),
  showError: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../../services', () => ({
  casService: { create: mocks.create },
  hsmService: { getProviders: mocks.getProviders, getSigningKeys: vi.fn() },
}))

vi.mock('../../../contexts', () => ({
  useNotification: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }),
}))

vi.mock('../../../hooks', () => ({
  useWebSocket: () => ({ muteToasts: vi.fn() }),
}))

vi.mock('../../../lib/utils', () => ({
  extractData: (r) => r?.data ?? r,
  cn: (...a) => a.filter(Boolean).join(' '),
  downloadBlob: vi.fn(),
}))

vi.mock('../../../components', () => ({
  Modal: ({ open, children }) => (open ? <div>{children}</div> : null),
  Button: ({ children, ...props }) => <button {...props}>{children}</button>,
  Input: ({ label, ...props }) => <input aria-label={label || props.name} {...props} />,
  Select: ({ label, options = [], value, onChange }) => (
    <select
      aria-label={label}
      value={value ?? ''}
      onChange={(e) => onChange?.(e.target.value)}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  ),
}))

import { CreateCAModal } from '../CreateCAModal'

async function openModal() {
  mocks.getProviders.mockResolvedValue({ data: [] })
  mocks.create.mockResolvedValue({ data: { id: 1 } })
  render(<CreateCAModal open onClose={vi.fn()} cas={[]} onSuccess={vi.fn()} />)
  // Advanced Constraints is collapsed by default
  fireEvent.click(screen.getByText('cas.advancedConstraints'))
}

function fillCommonName() {
  fireEvent.change(screen.getByLabelText('common.commonName (CN)'), {
    target: { value: 'Org Root CA' },
  })
}

function submit() {
  fireEvent.click(screen.getByText('common.createCA'))
}

describe('CreateCAModal name constraints', () => {
  beforeEach(() => vi.clearAllMocks())

  it('sends permitted rows as {type, value} objects and drops blank rows', async () => {
    await openModal()
    fillCommonName()

    fireEvent.click(screen.getByText('cas.nameConstraintAddPermitted'))
    fireEvent.click(screen.getByText('cas.nameConstraintAddPermitted'))
    const valueInputs = screen.getAllByPlaceholderText('cas.nameConstraintValuePlaceholder')
    fireEvent.change(valueInputs[0], { target: { value: '  example.com  ' } })
    // valueInputs[1] left blank on purpose

    submit()

    await waitFor(() => expect(mocks.create).toHaveBeenCalled())
    const payload = mocks.create.mock.calls[0][0]
    expect(payload.nameConstraintsPermitted).toEqual([{ type: 'dns', value: 'example.com' }])
    expect(payload.nameConstraintsExcluded).toBeUndefined()
  })

  it('hides the fields and omits constraints for an external-CSR CA', async () => {
    await openModal()
    fillCommonName()

    fireEvent.click(screen.getByText('cas.nameConstraintAddPermitted'))
    fireEvent.change(screen.getByPlaceholderText('cas.nameConstraintValuePlaceholder'), {
      target: { value: 'example.com' },
    })

    fireEvent.change(screen.getByLabelText('common.type'), { target: { value: 'external' } })

    expect(screen.queryByText('cas.nameConstraintAddPermitted')).not.toBeInTheDocument()
    expect(screen.getByText('cas.nameConstraintsExternalNote')).toBeInTheDocument()

    submit()

    await waitFor(() => expect(mocks.create).toHaveBeenCalled())
    const payload = mocks.create.mock.calls[0][0]
    expect(payload.nameConstraintsPermitted).toBeUndefined()
    expect(payload.type).toBe('external')
  })
})
