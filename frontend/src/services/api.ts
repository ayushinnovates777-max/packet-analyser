import axios from 'axios';

import { API_URL } from '../config';

const api = axios.create({
  baseURL: API_URL,
});

export const uploadPcap = async (file: File, onUploadProgress?: (progressEvent: any) => void) => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post('/analysis/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress,
  });

  return response.data;
};
