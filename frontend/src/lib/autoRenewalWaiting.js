// The expiring certificates an auto-renewal pass left alone, by reason (#387);
// null when there are none.
export function autoRenewalWaitingMessage(waiting, t) {
  const parts = Object.entries(waiting || {})
    .filter(([, count]) => count > 0)
    .map(([reason, count]) => t(`settings.autoRenewalWaiting_${reason}`, { count }))
  return parts.length ? t('settings.autoRenewalWaiting', { details: parts.join(', ') }) : null
}
