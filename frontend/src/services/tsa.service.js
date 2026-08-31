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
  }
}
