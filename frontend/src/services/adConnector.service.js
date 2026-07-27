import { apiClient } from './apiClient'

const adConnectorService = {
  get: () =>
    apiClient.get('/ad-connector'),

  save: (data) =>
    apiClient.put('/ad-connector', data),

  // Test unsaved form data
  test: (data) =>
    apiClient.post('/ad-connector/test', data),

  // Test the saved configuration
  testSaved: () =>
    apiClient.post('/ad-connector/test-saved'),
}

export { adConnectorService }
