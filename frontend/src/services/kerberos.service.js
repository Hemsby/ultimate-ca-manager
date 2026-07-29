import { apiClient } from './apiClient'

const kerberosService = {
  get: () =>
    apiClient.get('/kerberos/config'),

  update: (data) =>
    apiClient.patch('/kerberos/config', data),

  uploadKeytab: (file) => {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.upload('/kerberos/keytab', formData)
  },
}

export { kerberosService }
