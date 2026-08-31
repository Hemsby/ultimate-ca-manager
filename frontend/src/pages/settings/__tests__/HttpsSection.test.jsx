import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../../components', () => ({
  Button: ({ children, ...props }) => <button {...props}>{children}</button>,
  Badge: ({ children }) => <span>{children}</span>,
  DetailHeader: ({ title }) => <header>{title}</header>,
  DetailSection: ({ title, children }) => <section><h2>{title}</h2>{children}</section>,
  DetailGrid: ({ children }) => <div>{children}</div>,
  DetailField: ({ label, value }) => <div>{label}{value}</div>,
  DetailContent: ({ children }) => <div>{children}</div>,
}))

import HttpsSection from '../HttpsSection'

const renderSection = (httpsInfo, onUnbindHttpsCert = vi.fn()) => {
  render(
    <HttpsSection
      httpsInfo={httpsInfo}
      selectedHttpsCert={null}
      setSelectedHttpsCert={vi.fn()}
      setShowCertPicker={vi.fn()}
      handleApplyUcmCert={vi.fn()}
      handleRegenerateHttpsCert={vi.fn()}
      setShowHttpsImportModal={vi.fn()}
      onUnbindHttpsCert={onUnbindHttpsCert}
    />
  )
  return onUnbindHttpsCert
}

describe('HttpsSection bound certificate indicator (#303 follow-up)', () => {
  it('shows the bound certificate and triggers unbind', () => {
    const onUnbind = renderSection({
      type: 'CA-Signed',
      bound_certificate: { refid: 'ref-1', descr: 'Web UI cert', exists: true },
    })
    expect(screen.getByText(/settings\.httpsBound: Web UI cert/)).toBeInTheDocument()
    expect(screen.getByText('settings.httpsBoundDesc')).toBeInTheDocument()
    fireEvent.click(screen.getByText('settings.httpsUnbind'))
    expect(onUnbind).toHaveBeenCalled()
  })

  it('renders nothing about binding when no certificate is bound', () => {
    renderSection({ type: 'Self-Signed' })
    expect(screen.queryByText(/settings\.httpsBound/)).not.toBeInTheDocument()
    expect(screen.queryByText('settings.httpsUnbind')).not.toBeInTheDocument()
  })
})
