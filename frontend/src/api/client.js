import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const submitRepository = (data) => {
  return api.post('/v1/submit', data);
};

export const listProjects = () => {
  return api.get('/v1/projects');
};

export const getProject = (id) => {
  return api.get(`/v1/projects/${id}`);
};

export const updateProject = (id, data) => {
  return api.put(`/v1/projects/${id}`, data);
};

export const regenerateReport = (id) => {
  return api.post(`/v1/projects/${id}/regenerate`);
};

export const getProjectReports = (projectId) => {
  return api.get(`/v1/projects/${projectId}/reports`);
};

export const getReport = (id) => {
  return api.get(`/v1/reports/${id}`);
};

export const getReportHTML = (id) => {
  return `${API_BASE_URL}/v1/reports/${id}/html`;
};

export const getReportGraph = (id) => {
  return `${API_BASE_URL}/v1/reports/${id}/graph`;
};

export const listDependencies = (type = '') => {
  const url = type ? `/v1/dependencies?type=${type}` : '/v1/dependencies';
  return api.get(url);
};

export const getDependencyStats = () => {
  return api.get('/v1/dependencies/stats');
};

export default api;
