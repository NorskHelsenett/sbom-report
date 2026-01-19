import { useState, useEffect } from 'react';
import { listProjects, getProject, getProjectReports, getReportHTML, getReportGraph, updateProject } from '../api/client';

function ProjectsPage() {
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedProject, setSelectedProject] = useState(null);
  const [projectReports, setProjectReports] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [updateForm, setUpdateForm] = useState({
    name: '',
    description: '',
    github_token: '',
    regenerate: false
  });
  const [updateLoading, setUpdateLoading] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    setLoading(true);
    try {
      const response = await listProjects();
      setProjects(response.data.projects || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const viewProject = async (projectId) => {
    try {
      const [projectRes, reportsRes] = await Promise.all([
        getProject(projectId),
        getProjectReports(projectId)
      ]);
      setSelectedProject(projectRes.data);
      setProjectReports(reportsRes.data.reports || []);
      setShowModal(true);
    } catch (err) {
      setError(err.message);
    }
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedProject(null);
    setProjectReports([]);
  };

  const openUpdateModal = async (projectId) => {
    try {
      const projectRes = await getProject(projectId);
      const project = projectRes.data;
      setSelectedProject(project);
      setUpdateForm({
        name: project.name,
        description: project.description || '',
        github_token: '',
        regenerate: false
      });
      setShowUpdateModal(true);
      setUpdateSuccess(false);
    } catch (err) {
      setError(err.message);
    }
  };

  const closeUpdateModal = () => {
    setShowUpdateModal(false);
    setSelectedProject(null);
    setUpdateForm({
      name: '',
      description: '',
      github_token: '',
      regenerate: false
    });
    setUpdateSuccess(false);
  };

  const handleUpdateSubmit = async (e) => {
    e.preventDefault();
    setUpdateLoading(true);
    setUpdateSuccess(false);

    try {
      await updateProject(selectedProject.id, updateForm);
      setUpdateSuccess(true);
      setTimeout(() => {
        closeUpdateModal();
        loadProjects();
      }, 2000);
    } catch (err) {
      setError(err.message);
    } finally {
      setUpdateLoading(false);
    }
  };

  if (loading) return <div className="page"><div className="loading">Loading projects...</div></div>;
  if (error) return <div className="page"><div className="result error">Error: {error}</div></div>;

  return (
    <div className="page">
      <div className="card">
        <div className="card-header">
          <h2>Projects</h2>
          <button className="btn btn-secondary" onClick={loadProjects}>Refresh</button>
        </div>

        {projects.length === 0 ? (
          <div className="empty-state">
            <h3>No projects yet</h3>
            <p>Submit a repository to get started</p>
          </div>
        ) : (
          <div className="list-container">
            {projects.map(project => (
              <div key={project.id} className="project-item">
                <h3>{project.name}</h3>
                <a href={project.repo_url} className="project-url" target="_blank" rel="noopener noreferrer">
                  {project.repo_url}
                </a>
                <div className="project-actions">
                  <button className="btn btn-link" onClick={() => viewProject(project.id)}>
                    View Details
                  </button>
                  <button className="btn btn-secondary" onClick={() => openUpdateModal(project.id)}>
                    Update / Regenerate
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && selectedProject && (
        <div className="modal" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <span className="close" onClick={closeModal}>&times;</span>
            <h2>{selectedProject.name}</h2>
            <p><a href={selectedProject.repo_url} target="_blank" rel="noopener noreferrer">{selectedProject.repo_url}</a></p>
            {selectedProject.description && <p>{selectedProject.description}</p>}

            <h3 style={{ marginTop: '30px' }}>Reports ({projectReports.length})</h3>
            <div className="report-list">
              {projectReports.length === 0 ? <p>No reports yet</p> : projectReports.map(report => (
                <div key={report.id} className="report-item">
                  <h4>Report #{report.id}</h4>
                  <p><small>Generated: {new Date(report.generated_at).toLocaleString()}</small></p>
                  <div className="report-stats">
                    <div className="report-stat">
                      <strong>{report.total_dependencies}</strong>
                      <span>Dependencies</span>
                    </div>
                    <div className="report-stat">
                      <strong>{report.total_vulns}</strong>
                      <span>Vulnerabilities</span>
                    </div>
                  </div>
                  <div style={{ marginTop: '10px' }}>
                    <a href={getReportHTML(report.id)} target="_blank" rel="noopener noreferrer" className="btn btn-link">
                      View HTML Report
                    </a>
                    <a href={getReportGraph(report.id)} target="_blank" rel="noopener noreferrer" className="btn btn-link">
                      View Dependency Graph
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {showUpdateModal && selectedProject && (
        <div className="modal" onClick={closeUpdateModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <span className="close" onClick={closeUpdateModal}>&times;</span>
            <h2>Update Project</h2>
            <p><small>{selectedProject.repo_url}</small></p>

            <form onSubmit={handleUpdateSubmit}>
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={updateForm.name}
                  onChange={(e) => setUpdateForm({ ...updateForm, name: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  rows="3"
                  value={updateForm.description}
                  onChange={(e) => setUpdateForm({ ...updateForm, description: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label>GitHub Token (PAT)</label>
                <input
                  type="password"
                  value={updateForm.github_token}
                  onChange={(e) => setUpdateForm({ ...updateForm, github_token: e.target.value })}
                  placeholder="ghp_xxxxxxxxxxxx"
                />
                <small>Provide a new token if you want to regenerate the report</small>
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <input
                    type="checkbox"
                    checked={updateForm.regenerate}
                    onChange={(e) => setUpdateForm({ ...updateForm, regenerate: e.target.checked })}
                    style={{ width: 'auto' }}
                  />
                  <span>Regenerate SBOM report</span>
                </label>
                <small>Check this to create a new report with the updated token</small>
              </div>

              {updateSuccess && (
                <div className="result success">
                  Project updated successfully! {updateForm.regenerate && 'Report regeneration started.'}
                </div>
              )}

              {error && <div className="result error">Error: {error}</div>}

              <button type="submit" className="btn btn-primary" disabled={updateLoading}>
                {updateLoading ? 'Updating...' : 'Update Project'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default ProjectsPage;
