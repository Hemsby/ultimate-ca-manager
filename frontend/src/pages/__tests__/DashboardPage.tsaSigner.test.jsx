/**
 * DashboardPage — TSA signer visibility (#312 / PR #315).
 *
 * The dedicated RFC 3161 signer is a single point of failure for /tsa. The
 * dashboard must:
 *  - render the TSA System Health badge in its `warning` state (amber, not the
 *    grey offline box) when the signer is near expiry, and expose the backend
 *    status message as the hover title,
 *  - render it offline when the signer is unusable,
 *  - tag the configured signer's row in Next Expirations with a "TSA signer"
 *    chip (is_tsa_signer from the API).
 *
 * Reuses the shared page-rendering mocks; the dashboard-service mock there
 * predates these endpoints, so we attach getSystemStatus / getNextExpirations
 * to the same mock object per test.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import './pageRenderingSetup.jsx'
import { dashboardService } from '../../services/dashboard.service'

import DashboardPage from '../DashboardPage'

const NOW = new Date().toISOString()
const FUTURE = new Date(Date.now() + 20 * 864e5).toISOString()

function renderDashboard() {
  return render(<MemoryRouter><DashboardPage /></MemoryRouter>)
}

// The badge is the <div title=...> that wraps the label whose text is "TSA".
function tsaBadge() {
  return screen.getAllByText('TSA')[0].closest('div[title]')
}

describe('DashboardPage — TSA signer visibility (#312)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    dashboardService.getStats = vi.fn().mockResolvedValue({ data: {} })
    dashboardService.getRecentCAs = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getActivityLog = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getCertificateTrend = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getSystemStatus = vi.fn().mockResolvedValue({
      data: { tsa: { status: 'online', message: 'Dedicated signer' } },
    })
    dashboardService.getNextExpirations = vi.fn().mockResolvedValue({ data: [] })
  })

  it('renders the TSA badge in the warning state with the status message on hover', async () => {
    dashboardService.getSystemStatus.mockResolvedValue({
      data: { tsa: { status: 'warning', message: 'Signer expires in 12 day(s)' } },
    })
    renderDashboard()

    const badge = await waitFor(() => {
      const b = tsaBadge()
      expect(b).toBeTruthy()
      return b
    })
    expect(badge.getAttribute('title')).toBe('Signer expires in 12 day(s)')
    expect(badge.className).toMatch(/warning/)
  })

  it('renders the TSA badge offline (not warning, not success) when the signer is unusable', async () => {
    dashboardService.getSystemStatus.mockResolvedValue({
      data: { tsa: { status: 'offline', message: 'Signer certificate is revoked' } },
    })
    renderDashboard()

    const badge = await waitFor(() => {
      const b = tsaBadge()
      expect(b?.getAttribute('title')).toBe('Signer certificate is revoked')
      return b
    })
    expect(badge.className).not.toMatch(/warning/)
    expect(badge.className).not.toMatch(/success/)
  })

  it('tags the configured signer row in Next Expirations with the TSA signer chip', async () => {
    dashboardService.getNextExpirations.mockResolvedValue({
      data: [
        { id: 1, refid: 'sig', common_name: 'UCM Timestamp Signer', valid_from: NOW, valid_to: FUTURE, is_tsa_signer: true },
        { id: 2, refid: 'plain', common_name: 'web.example.com', valid_from: NOW, valid_to: FUTURE, is_tsa_signer: false },
      ],
    })
    renderDashboard()

    const signerRow = (await screen.findByText('UCM Timestamp Signer')).closest('div.flex')
    expect(within(signerRow).getByText('dashboard.tsaSigner')).toBeInTheDocument()

    const plainRow = screen.getByText('web.example.com').closest('div.flex')
    expect(within(plainRow).queryByText('dashboard.tsaSigner')).toBeNull()
  })
})
