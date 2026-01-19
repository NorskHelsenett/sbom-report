import { useState, useEffect } from 'react';
import { getDependencyStats } from '../api/client';

function StatsPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    setLoading(true);
    try {
      const response = await getDependencyStats();
      setStats(response.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="page"><div className="loading">Loading statistics...</div></div>;
  if (error) return <div className="page"><div className="result error">Error: {error}</div></div>;

  return (
    <div className="page">
      <div className="card">
        <div className="card-header">
          <h2>Dependency Statistics</h2>
          <button className="btn btn-secondary" onClick={loadStats}>Refresh</button>
        </div>

        <div className="stats-container">
          <div className="stats-grid">
            <div className="stat-card">
              <h3>{stats.total_dependencies}</h3>
              <p>Total Unique Dependencies</p>
            </div>
            {Object.entries(stats.by_type || {}).map(([type, count]) => (
              <div key={type} className="stat-card">
                <h3>{count}</h3>
                <p>{type.toUpperCase()} packages</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default StatsPage;
