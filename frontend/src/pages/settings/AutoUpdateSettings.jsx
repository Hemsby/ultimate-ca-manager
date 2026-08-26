/**
 * AutoUpdateSettings — scheduled update check channel + opt-in unattended
 * install (#301). Only the editable fields are sent back on save.
 */
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Button, Select } from '../../components'
import { ToggleSwitch } from '../../components/ui/ToggleSwitch'
import { apiClient } from '../../services'
import { useNotification } from '../../contexts'

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, h) => ({
  value: h,
  label: `${String(h).padStart(2, '0')}:00`,
}))

export default function AutoUpdateSettings() {
  const { t } = useTranslation()
  const { showSuccess, showError } = useNotification()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [canAutoUpdate, setCanAutoUpdate] = useState(true)
  const [channel, setChannel] = useState('stable')
  const [autoInstall, setAutoInstall] = useState(false)
  const [hour, setHour] = useState(3)

  useEffect(() => {
    let cancelled = false
    apiClient.get('/system/updates/settings')
      .then((response) => {
        if (cancelled) return
        const data = response?.data || response || {}
        setChannel(data.channel || 'stable')
        setAutoInstall(!!data.auto_install)
        setHour(Number.isInteger(data.hour) ? data.hour : 3)
        setCanAutoUpdate(data.can_auto_update !== false)
      })
      .catch(() => {})
      .finally(() => !cancelled && setLoading(false))
    return () => { cancelled = true }
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      await apiClient.patch('/system/updates/settings', {
        channel,
        auto_install: autoInstall,
        hour,
      })
      showSuccess(t('settings.autoUpdateSaved'))
    } catch (err) {
      showError(err?.message || t('settings.autoUpdateSaveFailed'))
    } finally {
      setSaving(false)
    }
  }

  if (loading) return null

  return (
    <Card className="p-4 space-y-4">
      <div>
        <h3 className="font-medium text-text-primary">{t('settings.autoUpdateTitle')}</h3>
        <p className="text-sm text-text-secondary mt-1">{t('settings.autoUpdateDesc')}</p>
      </div>

      <Select
        label={t('settings.autoUpdateChannel')}
        value={channel}
        onChange={(val) => setChannel(val)}
        options={[
          { value: 'stable', label: t('settings.autoUpdateChannelStable') },
          { value: 'rc', label: t('settings.autoUpdateChannelRc') },
        ]}
      />

      <ToggleSwitch
        checked={autoInstall}
        onChange={(val) => setAutoInstall(val)}
        label={t('settings.autoUpdateEnable')}
        description={canAutoUpdate
          ? t('settings.autoUpdateEnableDesc')
          : t('settings.autoUpdateDockerHint')}
        disabled={!canAutoUpdate}
      />

      {autoInstall && canAutoUpdate && (
        <Select
          label={t('settings.autoUpdateHour')}
          value={hour}
          onChange={(val) => setHour(Number(val))}
          options={HOUR_OPTIONS}
        />
      )}

      <div className="flex justify-end pt-2 border-t border-border">
        <Button type="button" variant="primary" onClick={handleSave} loading={saving}>
          {t('common.save')}
        </Button>
      </div>
    </Card>
  )
}
