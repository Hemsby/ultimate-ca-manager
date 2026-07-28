import { apiClient } from './apiClient'

const kerberosService = {
  get: () =>
    apiClient.get('/kerberos/config'),
}

export { kerberosService }
