/**
 * TSA (Time Stamp Authority) Service — RFC 3161
 */
import { apiClient } from './apiClient'

export const tsaService = {
  async getConfig() {
    return apiClient.get('/tsa/config')
  },

  async updateConfig(data) {
    return apiClient.patch('/tsa/config', data)
  },

  async getStats() {
    return apiClient.get('/tsa/stats')
  },

  async getSignerCandidates() {
    return apiClient.get('/tsa/signer-candidates')
  },

  // One-click issuance of a dedicated RFC 3161 signing certificate (#312).
  async issueSignerCertificate(payload = {}) {
    return apiClient.post('/tsa/signer-certificate', payload)
  }
}
