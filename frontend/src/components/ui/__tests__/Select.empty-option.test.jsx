/**
 * #303 (minor 1): empty-value options ("No template") must be rendered and
 * selectable — Radix forbids value="" on items, so the wrapper maps '' to an
 * internal sentinel instead of filtering the option out.
 *
 * jsdom lacks the pointer-capture and scrollIntoView APIs Radix Select
 * relies on; they are polyfilled here (no-ops) so the portal can open.
 */
import { describe, it, expect, vi, beforeAll } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Select } from '../Select'

beforeAll(() => {
  // The global setup mocks ResizeObserver with a non-constructible arrow
  // function; @floating-ui (Radix popper) does `new ResizeObserver(...)`.
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

const OPTIONS = [
  { value: '', label: 'No template' },
  { value: '1', label: 'Web Server' },
]

describe('Select empty-value option', () => {
  it('renders the empty-value option in the open list', async () => {
    const user = userEvent.setup()
    render(<Select options={OPTIONS} value="1" onChange={() => {}} />)
    await user.click(screen.getByRole('combobox'))
    expect(await screen.findByRole('option', { name: 'No template' })).toBeInTheDocument()
  })

  it('selecting it calls onChange with the empty string', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<Select options={OPTIONS} value="1" onChange={onChange} />)
    await user.click(screen.getByRole('combobox'))
    await user.click(await screen.findByRole('option', { name: 'No template' }))
    expect(onChange).toHaveBeenCalledWith('')
  })

  it('shows the empty option label when value is empty', () => {
    render(<Select options={OPTIONS} value="" onChange={() => {}} />)
    expect(screen.getByRole('combobox')).toHaveTextContent('No template')
  })
})
