import { useState, useEffect } from 'react';
import { listDependencies } from '../api/client';

function DependenciesPage() {
  const [dependencies, setDependencies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');

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

  if (loading) return <div className="page"><div className="loading">Loading dependencies...</div></div>;
  if (error) return <div className="page"><div className="result error">Error: {error}</div></div>;

  return (
    <div className="page">
      <div className="card">
        <div className="card-header">
          <h2>Dependencies</h2>
          <div className="filter-group">
            <label htmlFor="dep-type">Filter by type:</label>
            <select id="dep-type" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All</option>
              <option value="go">Go</option>
              <option value="npm">NPM</option>
              <option value="python">Python</option>
              <option value="maven">Maven</option>
            </select>
            <button className="btn btn-secondary" onClick={loadDependencies}>Refresh</button>
          </div>
        </div>

        {dependencies.length === 0 ? (
          <div className="empty-state">
            <h3>No dependencies found</h3>
          </div>
        ) : (
          <div className="list-container">
            {dependencies.map(dep => (
              <div key={dep.id} className="dependency-item">
                <h3>
                  <span className={`badge badge-${dep.package_type}`}>{dep.package_type}</span>
                  {dep.name}@{dep.version}
                </h3>
                {dep.description && <p>{dep.description}</p>}
                {dep.repo_url && <p><a href={dep.repo_url} target="_blank" rel="noopener noreferrer">{dep.repo_url}</a></p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default DependenciesPage;
