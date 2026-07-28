import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { WindowsLogo, Globe, Certificate, ArrowsClockwise, FloppyDisk } from '@phosphor-icons/react'
import { Button, Input, Select, DetailHeader, DetailSection, DetailContent } from '../../components'
import { ToggleSwitch } from '../../components/ui/ToggleSwitch'
import { xcepWstepService, casService } from '../../services'
import { useNotification } from '../../contexts'
import CopyableUrl from './CopyableUrl'

const EMPTY_XCEP = { enabled: false, ca_id: null, username: '', password_set: false }
const EMPTY_WSTEP = { enabled: false, ca_id: null, username: '', password_set: false, validity_days: 365 }

export default function XcepWstepSection() {
  const { t } = useTranslation()
  const { showSuccess, showError } = useNotification()
  const baseUrl = typeof window !== 'undefined' ? window.location.origin : ''

  const [cas, setCas] = useState([])
  const [loading, setLoading] = useState(true)

  const [xcep, setXcep] = useState(EMPTY_XCEP)
  const [xcepPassword, setXcepPassword] = useState('')
  const [xcepSaving, setXcepSaving] = useState(false)

  const [wstep, setWstep] = useState(EMPTY_WSTEP)
  const [wstepPassword, setWstepPassword] = useState('')
  const [wstepSaving, setWstepSaving] = useState(false)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [casRes, xcepRes, wstepRes] = await Promise.all([
        casService.getAll(),
        xcepWstepService.getXcep(),
        xcepWstepService.getWstep(),
      ])
      setCas(casRes.data || [])
      setXcep(xcepRes.data || EMPTY_XCEP)
      setWstep(wstepRes.data || EMPTY_WSTEP)
    } catch (error) {
      showError(error.message || t('messages.errors.loadFailed.generic'))
    } finally {
      setLoading(false)
    }
  }, [showError, t])

  useEffect(() => { loadAll() }, [loadAll])

  const caOptions = cas.map(ca => ({ value: String(ca.id), label: ca.descr || ca.common_name }))

  const handleXcepSave = async () => {
    setXcepSaving(true)
    try {
      const payload = { enabled: xcep.enabled, ca_id: xcep.ca_id, username: xcep.username }
      if (xcepPassword) payload.password = xcepPassword
      await xcepWstepService.updateXcep(payload)
      showSuccess(t('messages.success.update.settings'))
      setXcepPassword('')
      loadAll()
    } catch (error) {
      showError(error.message || t('messages.errors.updateFailed.settings'))
    } finally {
      setXcepSaving(false)
    }
  }

  const handleWstepSave = async () => {
    setWstepSaving(true)
    try {
      const payload = { enabled: wstep.enabled, ca_id: wstep.ca_id, username: wstep.username, validity_days: wstep.validity_days }
      if (wstepPassword) payload.password = wstepPassword
      await xcepWstepService.updateWstep(payload)
      showSuccess(t('messages.success.update.settings'))
      setWstepPassword('')
      loadAll()
    } catch (error) {
      showError(error.message || t('messages.errors.updateFailed.settings'))
    } finally {
      setWstepSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="w-6 h-6 border-2 border-accent-primary-op30 border-t-accent-primary rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <DetailContent>
      <DetailHeader
        icon={WindowsLogo}
        title={t('xcepWstep.title')}
        subtitle={t('xcepWstep.subtitle')}
      />

      <DetailSection title={t('xcepWstep.xcepTitle')} icon={Globe} iconClass="icon-bg-cyan">
        <div className="space-y-4">
          <p className="text-xs text-text-secondary">{t('xcepWstep.xcepDescription')}</p>
          <ToggleSwitch
            label={t('common.enabled')}
            checked={xcep.enabled}
            onChange={(val) => setXcep(prev => ({ ...prev, enabled: val }))}
          />
          <Select
            label={t('xcepWstep.ca')}
            value={xcep.ca_id ? String(xcep.ca_id) : ''}
            onChange={(val) => setXcep(prev => ({ ...prev, ca_id: val ? parseInt(val, 10) : null }))}
            options={caOptions}
            placeholder={t('xcepWstep.selectCa')}
          />
          <div className="grid grid-cols-2 gap-4">
            <Input
              label={t('common.username')}
              value={xcep.username || ''}
              onChange={(e) => setXcep(prev => ({ ...prev, username: e.target.value }))}
            />
            <Input
              label={t('common.password')}
              type="password"
              value={xcepPassword}
              onChange={(e) => setXcepPassword(e.target.value)}
              placeholder={xcep.password_set ? '••••••••' : ''}
            />
          </div>
          <div className="flex justify-end pt-4 border-t border-border">
            <Button type="button" onClick={handleXcepSave} disabled={xcepSaving}>
              {xcepSaving ? <ArrowsClockwise size={14} className="animate-spin" /> : <FloppyDisk size={14} />}
              {t('common.save')}
            </Button>
          </div>
        </div>
      </DetailSection>

      <DetailSection title={t('xcepWstep.wstepTitle')} icon={Certificate} iconClass="icon-bg-blue">
        <div className="space-y-4">
          <p className="text-xs text-text-secondary">{t('xcepWstep.wstepDescription')}</p>
          <ToggleSwitch
            label={t('common.enabled')}
            checked={wstep.enabled}
            onChange={(val) => setWstep(prev => ({ ...prev, enabled: val }))}
          />
          <Select
            label={t('xcepWstep.ca')}
            value={wstep.ca_id ? String(wstep.ca_id) : ''}
            onChange={(val) => setWstep(prev => ({ ...prev, ca_id: val ? parseInt(val, 10) : null }))}
            options={caOptions}
            placeholder={t('xcepWstep.selectCa')}
          />
          <div className="grid grid-cols-2 gap-4">
            <Input
              label={t('common.username')}
              value={wstep.username || ''}
              onChange={(e) => setWstep(prev => ({ ...prev, username: e.target.value }))}
            />
            <Input
              label={t('common.password')}
              type="password"
              value={wstepPassword}
              onChange={(e) => setWstepPassword(e.target.value)}
              placeholder={wstep.password_set ? '••••••••' : ''}
            />
          </div>
          <Input
            label={t('xcepWstep.validityDays')}
            type="number"
            value={wstep.validity_days || 365}
            onChange={(e) => setWstep(prev => ({ ...prev, validity_days: parseInt(e.target.value, 10) || 365 }))}
          />
          <div className="flex justify-end pt-4 border-t border-border">
            <Button type="button" onClick={handleWstepSave} disabled={wstepSaving}>
              {wstepSaving ? <ArrowsClockwise size={14} className="animate-spin" /> : <FloppyDisk size={14} />}
              {t('common.save')}
            </Button>
          </div>
        </div>
      </DetailSection>

      {xcep.enabled && (
        <DetailSection title={t('xcepWstep.urlsTitle')} icon={Globe} iconClass="icon-bg-violet">
          <div className="space-y-3">
            <CopyableUrl
              label={t('xcepWstep.urlUsernamePassword')}
              value={`${baseUrl}/ADPolicyProvider_CEP_UsernamePassword/service.svc`}
              description={t('xcepWstep.urlUsernamePasswordDesc')}
            />
            <CopyableUrl
              label={t('xcepWstep.urlKerberos')}
              value={`${baseUrl}/ADPolicyProvider_CEP_Kerberos/service.svc`}
              description={t('xcepWstep.urlKerberosDesc')}
            />
          </div>
        </DetailSection>
      )}
    </DetailContent>
  )
}
