import { useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom'
import SubmitPage from './pages/SubmitPage'
import ProjectsPage from './pages/ProjectsPage'
import DependenciesPage from './pages/DependenciesPage'
import StatsPage from './pages/StatsPage'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('submit')

  return (
    <Router>
      <div className="app">
        <header className="app-header">
          <h1>📦 SBOM Report Dashboard</h1>
          <p className="subtitle">Software Bill of Materials Analysis</p>
        </header>

        <nav className="tabs">
          <Link 
            to="/" 
            className={`tab-btn ${activeTab === 'submit' ? 'active' : ''}`}
            onClick={() => setActiveTab('submit')}
          >
            Submit Repository
          </Link>
          <Link 
            to="/projects" 
            className={`tab-btn ${activeTab === 'projects' ? 'active' : ''}`}
            onClick={() => setActiveTab('projects')}
          >
            Projects
          </Link>
          <Link 
            to="/dependencies" 
            className={`tab-btn ${activeTab === 'dependencies' ? 'active' : ''}`}
            onClick={() => setActiveTab('dependencies')}
          >
            Dependencies
          </Link>
          <Link 
            to="/stats" 
            className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
            onClick={() => setActiveTab('stats')}
          >
            Statistics
          </Link>
        </nav>

        <main className="content">
          <Routes>
            <Route path="/" element={<SubmitPage />} />
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/dependencies" element={<DependenciesPage />} />
            <Route path="/stats" element={<StatsPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App
