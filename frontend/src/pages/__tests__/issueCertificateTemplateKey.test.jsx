/**
 * #318: selecting an EC certificate template must carry its curve into the
 * issue form.
 *
 * handleTemplateChange sets key_type and key_size together, but the Key Size
 * <Select> swaps its option list (RSA sizes vs EC curves) on the key_type
 * change. Radix fires onValueChange when the previously selected item unmounts
 * during that swap; the wrapper used to forward it and blank key_size, so the
 * request went out as key_type=ecdsa with key_size='' and issuance failed.
 *
 * jsdom lacks the pointer-capture / scrollIntoView APIs Radix Select relies
 * on; they are polyfilled here so the portal can open.
 */
import { describe, it, expect, vi, beforeAll } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const EC_TEMPLATE = {
  id: 1,
  name: 'EC Web Server',
  template_type: 'web_server',
  key_type: 'EC-P256',
  validity_days: 397,
  dn_template: {},
  extensions_template: { extended_key_usage: ['serverAuth'] },
}

vi.mock('../../services', () => ({
  templatesService: {
    getAll: vi.fn().mockResolvedValue({ data: [EC_TEMPLATE] }),
    getForCA: vi.fn().mockResolvedValue({ data: [EC_TEMPLATE] }),
  },
  ekuService: { getKnown: vi.fn().mockResolvedValue({ data: { ekus: [] } }) },
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({ showError: vi.fn(), showSuccess: vi.fn(), showWarning: vi.fn() }),
}))

beforeAll(() => {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Element.prototype.hasPointerCapture = Element.prototype.hasPointerCapture || (() => false)
  Element.prototype.setPointerCapture = Element.prototype.setPointerCapture || (() => {})
  Element.prototype.releasePointerCapture = Element.prototype.releasePointerCapture || (() => {})
  Element.prototype.scrollIntoView = Element.prototype.scrollIntoView || (() => {})
})

const t = (key) => key

describe('IssueCertificateForm EC template key size (#318)', () => {
  it('carries the template curve into the submitted payload', async () => {
    const { IssueCertificateForm } = await import('../certificates/IssueCertificateForm')
    const user = userEvent.setup()
    const onSubmit = vi.fn().mockResolvedValue(undefined)

    const { container } = render(
      <IssueCertificateForm
        cas={[{ id: 1, descr: 'Test CA', subject: 'CN=Test CA' }]}
        onSubmit={onSubmit}
        onCancel={() => {}}
        t={t}
      />
    )

    // Wait for the template <Select> to render (it only appears once templates load)
    await screen.findByText('certificates.templateOptional')
    const templateTrigger = container.querySelectorAll('[role="combobox"]')[0]
    await user.click(templateTrigger)
    await user.click(await screen.findByRole('option', { name: 'EC Web Server' }))

    await user.type(screen.getByPlaceholderText('example.com'), 'ec-host.example.test')
    await user.click(container.querySelector('button[type="submit"]'))

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const payload = onSubmit.mock.calls[0][0]
    expect(payload.key_type).toBe('ecdsa')
    expect(payload.key_size).toBe('256')
  }, 15000)

  it('keeps a valid key size when Key Type is switched RSA -> ECDSA by hand', async () => {
    const { IssueCertificateForm } = await import('../certificates/IssueCertificateForm')
    const user = userEvent.setup()
    const onSubmit = vi.fn().mockResolvedValue(undefined)

    const { container } = render(
      <IssueCertificateForm
        cas={[{ id: 1, descr: 'Test CA', subject: 'CN=Test CA' }]}
        onSubmit={onSubmit}
        onCancel={() => {}}
        t={t}
      />
    )

    await screen.findByText('common.keyType')
    const keyTypeTrigger = screen.getByText('common.keyType')
      .closest('[class*="space-y"]').querySelector('[role="combobox"]')
    await user.click(keyTypeTrigger)
    await user.click(await screen.findByRole('option', { name: 'ECDSA' }))

    await user.type(screen.getByPlaceholderText('example.com'), 'manual-ec.example.test')
    await user.click(container.querySelector('button[type="submit"]'))

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const payload = onSubmit.mock.calls[0][0]
    expect(payload.key_type).toBe('ecdsa')
    expect(payload.key_size).toBe('256')
  }, 15000)
})
