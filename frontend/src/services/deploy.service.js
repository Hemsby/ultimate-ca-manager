/**
 * Deploy Hooks Service (#299) — admin-only
 * Push certificates to remote hosts over SSH/SFTP with a reload command.
 */
import { apiClient } from './apiClient'

export const deployService = {
  // Targets
  async getTargets() {
    return apiClient.get('/deploy/targets')
  },
  async getTarget(id) {
    return apiClient.get(`/deploy/targets/${id}`)
  },
  async createTarget(data) {
    return apiClient.post('/deploy/targets', data)
  },
  async updateTarget(id, data) {
    return apiClient.patch(`/deploy/targets/${id}`, data)
  },
  async deleteTarget(id) {
    return apiClient.delete(`/deploy/targets/${id}`)
  },
  async testTarget(id) {
    return apiClient.post(`/deploy/targets/${id}/test`)
  },

  // Bindings
  async getBindings(params = {}) {
    const query = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null)
    ).toString()
    return apiClient.get(`/deploy/bindings${query ? `?${query}` : ''}`)
  },
  async createBinding(data) {
    return apiClient.post('/deploy/bindings', data)
  },
  async updateBinding(id, data) {
    return apiClient.patch(`/deploy/bindings/${id}`, data)
  },
  async deleteBinding(id) {
    return apiClient.delete(`/deploy/bindings/${id}`)
  },
  async deployNow(bindingId) {
    return apiClient.post(`/deploy/bindings/${bindingId}/deploy`)
  },

  // Deliveries
  async getDeliveries(params = {}) {
    const query = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null)
    ).toString()
    return apiClient.get(`/deploy/deliveries${query ? `?${query}` : ''}`)
  },
  async retryDelivery(id) {
    return apiClient.post(`/deploy/deliveries/${id}/retry`)
  },
}
