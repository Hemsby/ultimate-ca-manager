import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { TestTube, FloppyDisk } from '@phosphor-icons/react'
import { Button, Input, Textarea } from '../../components'
import { adConnectorService } from '../../services'
import { useNotification } from '../../contexts'

export default function AdConnectorForm({ config, onSave, onCancel }) {
  const { t } = useTranslation()
  const { showSuccess, showError } = useNotification()
  const [testing, setTesting] = useState(false)
  const [formData, setFormData] = useState({
    server: config?.server || '',
    port: config?.port || 389,
    use_ssl: config?.use_ssl ?? false,
    verify_ssl: config?.verify_ssl ?? true,
    ca_bundle: config?.ca_bundle || '',
    base_dn: config?.base_dn || '',
    bind_dn: config?.bind_dn || '',
    bind_password: '',
    enabled: config?.enabled ?? false,
  })

  const updateField = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    const data = { ...formData }
    // Don't send the masked placeholder back if the password is unchanged
    if (config?.id && !data.bind_password) delete data.bind_password
    onSave(data)
  }

  const handleTestConnection = async () => {
    if (!formData.server) return
    setTesting(true)
    try {
      // Always test the current (possibly unsaved) form values -- testing
      // the saved config here would silently ignore any edit the user just
      // made (e.g. a corrected bind DN) until they hit Save.
      const response = await adConnectorService.test(formData)
      showSuccess(response.data?.message || t('adConnector.testSuccess'))
    } catch (error) {
      showError(error.message || t('adConnector.testFailed'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 space-y-4">
      <Input
        label={`${t('adConnector.server')} *`}
        value={formData.server}
        onChange={(e) => updateField('server', e.target.value)}
        placeholder={t('adConnector.serverPlaceholder')}
        required
      />
      <Input
        label={t('adConnector.port')}
        type="number"
        value={formData.port}
        onChange={(e) => updateField('port', parseInt(e.target.value, 10) || 389)}
      />

      <div className="flex items-center gap-4">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={formData.use_ssl} onChange={(e) => updateField('use_ssl', e.target.checked)} className="rounded" />
          {t('adConnector.useSsl')}
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={formData.verify_ssl} onChange={(e) => updateField('verify_ssl', e.target.checked)} className="rounded" />
          {t('adConnector.verifySsl')}
        </label>
      </div>

      {formData.verify_ssl && (
        <Textarea
          label={t('adConnector.caBundle')}
          value={formData.ca_bundle}
          onChange={(e) => updateField('ca_bundle', e.target.value)}
          rows={3}
          placeholder="-----BEGIN CERTIFICATE-----"
          className="font-mono text-xs"
        />
      )}

      <Input
        label={`${t('adConnector.baseDn')} *`}
        value={formData.base_dn}
        onChange={(e) => updateField('base_dn', e.target.value)}
        placeholder={t('adConnector.baseDnPlaceholder')}
        required
      />
      <Input
        label={`${t('adConnector.bindDn')} *`}
        value={formData.bind_dn}
        onChange={(e) => updateField('bind_dn', e.target.value)}
        placeholder={t('adConnector.bindDnPlaceholder')}
        required
      />
      <Input
        label={t('adConnector.bindPassword')}
        type="password"
        value={formData.bind_password}
        onChange={(e) => updateField('bind_password', e.target.value)}
        placeholder={config?.id ? '••••••••' : ''}
      />

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={formData.enabled} onChange={(e) => updateField('enabled', e.target.checked)} className="rounded" />
        {t('common.enabled')}
      </label>

      <div className="flex justify-between gap-2 pt-4 border-t border-border">
        <Button type="button" variant="secondary" onClick={handleTestConnection} disabled={!formData.server || testing}>
          <TestTube size={16} />
          {testing ? t('common.testing') : t('adConnector.testConnection')}
        </Button>
        <div className="flex gap-2">
          <Button type="button" variant="secondary" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button type="submit">
            <FloppyDisk size={16} />
            {t('common.save')}
          </Button>
        </div>
      </div>
    </form>
  )
}
