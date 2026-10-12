import { describe, it, expect } from 'vitest'
import i18n from 'i18next'
import en from '../../i18n/locales/en.json'
import uk from '../../i18n/locales/uk.json'
import { autoRenewalWaitingMessage } from '../autoRenewalWaiting'

const t = i18n.createInstance()
await t.init({ lng: 'en', resources: { en: { translation: en }, uk: { translation: uk } } })

describe('autoRenewalWaitingMessage (#387)', () => {
  it('names each reason with its count, skipping empty ones', () => {
    expect(autoRenewalWaitingMessage({ not_yet_due: 1, no_private_key: 0, source_excluded: 2 }, t.t))
      .toBe('Expiring but left for later: 1 not yet in the last third of its lifetime, 2 from sources not selected')
  })

  it('says nothing when nothing waits', () => {
    expect(autoRenewalWaitingMessage({ not_yet_due: 0, no_private_key: 0, source_excluded: 0 }, t.t)).toBeNull()
    expect(autoRenewalWaitingMessage(undefined, t.t)).toBeNull()
  })

  it('every reason the backend reports has a string in every plural form', () => {
    const tu = t.getFixedT('uk')
    for (const reason of ['not_yet_due', 'no_private_key', 'source_excluded']) {
      for (const count of [1, 3, 5]) {
        const text = tu(`settings.autoRenewalWaiting_${reason}`, { count })
        expect(text).not.toContain('autoRenewalWaiting')
        expect(text).toContain(String(count))
      }
    }
  })
})
