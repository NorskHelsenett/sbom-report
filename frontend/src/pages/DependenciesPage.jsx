import { useState, useEffect } from 'react';
import { listDependencies, getDependencyUsage } from '../api/client';

function DependenciesPage() {
  const [dependencies, setDependencies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDependency, setSelectedDependency] = useState(null);
  const [usageReports, setUsageReports] = useState([]);
  const [loadingUsage, setLoadingUsage] = useState(false);

  useEffect(() => {
    loadDependencies();
  }, [filter]);

  const loadDependencies = async () => {
    setLoading(true);
    try {
      const response = await listDependencies(filter);
      setDependencies(response.data || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDependencyClick = async (dep) => {
    setSelectedDependency(dep);
    setLoadingUsage(true);
    try {
      const response = await getDependencyUsage(dep.id);
      setUsageReports(response.data || []);
    } catch (err) {
      console.error('Failed to load dependency usage:', err);
      setUsageReports([]);
    } finally {
      setLoadingUsage(false);
    }
  };

  const closeModal = () => {
    setSelectedDependency(null);
    setUsageReports([]);
  };

  const filteredDependencies = dependencies.filter(dep => {
    if (!searchTerm) return true;
    return dep.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
           dep.version.toLowerCase().includes(searchTerm.toLowerCase());
  });

  const totalVulnerabilities = dependencies.filter(d => d.vuln_count > 0).length;

  if (loading) return <div className="page"><div className="loading">Loading dependencies...</div></div>;
  if (error) return <div className="page"><div className="result error">Error: {error}</div></div>;

  return (
    <div className="page">
      <div className="card">
        <div className="card-header">
          <h2>Dependencies ({dependencies.length})</h2>
          <div className="stats-row">
            <div className="stat-item">
              <span className="stat-label">With Vulnerabilities:</span>
              <span className="stat-value" style={{color: totalVulnerabilities > 0 ? '#ff6b6b' : '#51cf66'}}>
                {totalVulnerabilities}
              </span>
            </div>
          </div>
        </div>

        <div className="filter-controls">
          <div className="filter-group">
            <label htmlFor="dep-type">Filter by type:</label>
            <select id="dep-type" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All</option>
              <option value="go">Go</option>
              <option value="npm">NPM</option>
              <option value="python">Python</option>
              <option value="maven">Maven</option>
            </select>
          </div>
          <div className="filter-group">
            <label htmlFor="dep-search">Search:</label>
            <input
              id="dep-search"
              type="text"
              placeholder="Search dependencies..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{padding: '8px 12px', borderRadius: '4px', border: '1px solid #444', background: '#2a2a2a', color: '#fff'}}
            />
          </div>
          <button className="btn btn-secondary" onClick={loadDependencies}>Refresh</button>
        </div>

        {filteredDependencies.length === 0 ? (
          <div className="empty-state">
            <h3>{searchTerm ? 'No matching dependencies found' : 'No dependencies found'}</h3>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Projects Using</th>
                  <th>Vulnerabilities</th>
                </tr>
              </thead>
              <tbody>
                {filteredDependencies.map(dep => (
                  <tr 
                    key={dep.id} 
                    className={dep.vuln_count > 0 ? 'vuln-row clickable' : 'clickable'}
                    onClick={() => handleDependencyClick(dep)}
                    style={{cursor: 'pointer'}}
                  >
                    <td>
                      <span className={`badge badge-${dep.package_type}`}>{dep.package_type}</span>
                    </td>
                    <td>
                      <strong>{dep.name}</strong>
                      {dep.repo_url && (
                        <div style={{fontSize: '0.85em', marginTop: '4px'}}>
                          <a href={dep.repo_url} target="_blank" rel="noopener noreferrer" style={{color: '#51cf66'}}>
                            {dep.repo_url}
                          </a>
                        </div>
                      )}
                    </td>
                    <td><code>{dep.version}</code></td>
                    <td>
                      <span className="badge" style={{background: '#4263eb', color: '#fff'}}>
                        {dep.project_count || 0} {dep.project_count === 1 ? 'project' : 'projects'}
                      </span>
                    </td>
                    <td>
                      {dep.vuln_count > 0 ? (
                        <span className="badge" style={{background: '#ff6b6b', color: '#fff', fontWeight: 'bold'}}>
                          {dep.vuln_count} {dep.vuln_count === 1 ? 'CVE' : 'CVEs'}
                        </span>
                      ) : (
                        <span style={{color: '#868e96'}}>None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedDependency && (
        <div className="modal" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <span className="close" onClick={closeModal}>&times;</span>
            <h2>
              <span className={`badge badge-${selectedDependency.package_type}`}>
                {selectedDependency.package_type}
              </span>
              {' '}{selectedDependency.name}@{selectedDependency.version}
            </h2>
            
            {selectedDependency.vuln_count > 0 && (
              <div style={{marginTop: '10px', marginBottom: '20px'}}>
                <span className="badge" style={{background: '#ff6b6b', color: '#fff', fontSize: '1rem'}}>
                  ⚠️ {selectedDependency.vuln_count} {selectedDependency.vuln_count === 1 ? 'Vulnerability' : 'Vulnerabilities'}
                </span>
              </div>
            )}

            <h3 style={{marginTop: '20px', marginBottom: '15px'}}>Used in {selectedDependency.project_count || 0} {selectedDependency.project_count === 1 ? 'Project' : 'Projects'}</h3>
            
            {loadingUsage ? (
              <div className="loading">Loading project usage...</div>
            ) : usageReports.length === 0 ? (
              <div className="empty-state">
                <p>No projects found using this dependency.</p>
              </div>
            ) : (
              <div className="report-list">
                {usageReports.map(report => (
                  <div key={report.id} className="report-item">
                    <h4>{report.project?.name || report.base_dir}</h4>
                    <p style={{color: '#868e96', fontSize: '0.9rem'}}>
                      {report.project?.repo_url}
                    </p>
                    <div className="report-stats">
                      <div className="report-stat">
                        <span style={{color: '#868e96'}}>Dependencies</span>
                        <strong style={{color: '#51cf66'}}>{report.total_dependencies}</strong>
                      </div>
                      <div className="report-stat">
                        <span style={{color: '#868e96'}}>Vulnerabilities</span>
                        <strong style={{color: report.total_vulns > 0 ? '#ff6b6b' : '#51cf66'}}>
                          {report.total_vulns}
                        </strong>
                      </div>
                      <div className="report-stat">
                        <span style={{color: '#868e96'}}>Generated</span>
                        <strong style={{color: '#868e96', fontSize: '0.9rem'}}>
                          {new Date(report.generated_at).toLocaleDateString()}
                        </strong>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default DependenciesPage;
