import { useState } from 'react';
import { submitRepository } from '../api/client';

function SubmitPage() {
  const [formData, setFormData] = useState({
    repo_url: '',
    name: '',
    description: '',
    github_token: ''
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await submitRepository(formData);
      setResult(response.data);
      setFormData({ repo_url: '', name: '', description: '', github_token: '' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to submit repository');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <h2>Submit Repository for Analysis</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="repo_url">Repository URL *</label>
            <input
              type="url"
              id="repo_url"
              name="repo_url"
              value={formData.repo_url}
              onChange={handleChange}
              required
              placeholder="https://github.com/owner/repo"
            />
          </div>

          <div className="form-group">
            <label htmlFor="name">Project Name</label>
            <input
              type="text"
              id="name"
              name="name"
              value={formData.name}
              onChange={handleChange}
              placeholder="My Project (optional)"
            />
          </div>

          <div className="form-group">
            <label htmlFor="description">Description</label>
            <textarea
              id="description"
              name="description"
              value={formData.description}
              onChange={handleChange}
              rows="3"
              placeholder="Project description (optional)"
            />
          </div>

          <div className="form-group">
            <label htmlFor="github_token">GitHub Token (Optional)</label>
            <input
              type="password"
              id="github_token"
              name="github_token"
              value={formData.github_token}
              onChange={handleChange}
              placeholder="ghp_xxxxxxxxxxxx"
            />
            <small>Provide a token for higher rate limits and private repos</small>
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? '⏳ Analyzing...' : 'Analyze Repository'}
          </button>
        </form>

        {result && (
          <div className="result success">
            <h3>✅ Analysis Complete!</h3>
            <p><strong>Project ID:</strong> {result.project_id}</p>
            <p><strong>Report ID:</strong> {result.report_id}</p>
            <p><strong>Dependencies:</strong> {result.report.total_dependencies}</p>
            <p><strong>Vulnerabilities:</strong> {result.report.total_vulns}</p>
          </div>
        )}

        {error && (
          <div className="result error">
            <strong>Error:</strong> {error}
          </div>
        )}
      </div>
    </div>
  );
}

export default SubmitPage;
