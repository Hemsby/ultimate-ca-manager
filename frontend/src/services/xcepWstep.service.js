import { apiClient } from './apiClient'

const xcepWstepService = {
  getXcep: () =>
    apiClient.get('/xcep/config'),

  updateXcep: (data) =>
    apiClient.patch('/xcep/config', data),

  getWstep: () =>
    apiClient.get('/wstep/config'),

  updateWstep: (data) =>
    apiClient.patch('/wstep/config', data),
}

export { xcepWstepService }
