/**
 * Regression tests: stored XSS in the ACME ToS preview
 * (security audit v2.203, item #14).
 *
 * The preview used to be built by a hand-rolled regex sanitizer whose output
 * was passed to dangerouslySetInnerHTML. It escaped `<`, `>` and `&` but NOT
 * double quotes, and it never validated link schemes, so admin-supplied ToS
 * text could break out of the generated href attribute or inject
 * `[click](javascript:...)` — stored XSS against any operator viewing the ACME
 * settings page. (The server CSP blocked inline script execution in modern
 * browsers, so this was defence-in-depth, not a full bypass.)
 *
 * The component now renders through ReactMarkdown, which builds React elements
 * instead of interpolating HTML, plus a urlTransform that pins link schemes.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { TosPreview } from '../ConfigTab'

const jsUrl = ['java', 'script:alert(1)'].join('')

describe('TosPreview', () => {
  it('renders ordinary markdown', () => {
    const { container } = render(<TosPreview body={'Hello **world**'} />)
    expect(screen.getByText('world').tagName).toBe('STRONG')
    expect(container.textContent).toContain('Hello')
  })

  it('renders nothing for empty input', () => {
    const { container } = render(<TosPreview body={'   '} />)
    expect(container.innerHTML).toBe('')
  })

  it('keeps a normal https link and hardens the anchor', () => {
    render(<TosPreview body={'[terms](https://example.com/tos)'} />)
    const link = screen.getByRole('link', { name: 'terms' })
    expect(link.getAttribute('href')).toBe('https://example.com/tos')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(link.getAttribute('target')).toBe('_blank')
  })

  it('strips a javascript: link target', () => {
    render(<TosPreview body={`[click](${jsUrl})`} />)
    const link = screen.queryByRole('link', { name: 'click' })
    // Either the anchor is dropped entirely or its href is neutralised —
    // what must never happen is a live javascript: URL.
    expect(link?.getAttribute('href') ?? '').not.toContain('script:')
  })

  it('strips a data: link target', () => {
    render(<TosPreview body={'[x](data:text/html;base64,PHNjcmlwdD4=)'} />)
    const link = screen.queryByRole('link', { name: 'x' })
    expect(link?.getAttribute('href') ?? '').not.toContain('data:')
  })

  it('does not execute or inject raw HTML', () => {
    const payload = '<img src=x onerror="alert(1)">'
    const { container } = render(<TosPreview body={payload} />)
    // No real element is created; the markup survives as inert text.
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('[onerror]')).toBeNull()
    expect(container.textContent).toContain('<img')
  })

  it('does not let a quote break out of an attribute', () => {
    // The old sanitizer did not escape `"`, so this closed the generated href
    // and injected a new attribute. Assert on the DOM, not on the serialized
    // string: an escaped quote inside a text node is harmless and expected.
    const { container } = render(
      <TosPreview body={'[x](https://a" onmouseover="alert(1))'} />
    )
    expect(container.querySelector('[onmouseover]')).toBeNull()
    for (const el of container.querySelectorAll('*')) {
      for (const attr of el.attributes) {
        expect(attr.name.toLowerCase().startsWith('on')).toBe(false)
      }
    }
  })

  it('does not inject a script element', () => {
    const { container } = render(
      <TosPreview body={'<script>alert(1)</script>'} />
    )
    expect(container.querySelector('script')).toBeNull()
  })
})
