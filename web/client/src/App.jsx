import { useEffect } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import Dashboard from './pages/Dashboard.jsx';
import ScanForm from './pages/ScanForm.jsx';
import ScanLive from './pages/ScanLive.jsx';
import ScansList from './pages/ScansList.jsx';
import ScanDetail from './pages/ScanDetail.jsx';
import ScanReport from './pages/ScanReport.jsx';
import ToolsConfig from './pages/ToolsConfig.jsx';
import Repos from './pages/Repos.jsx';

// WCAG 2.4.2 Page Titled. A single-page app keeps the initial <title> across
// every route unless it is updated on navigation, so each view was announced
// under the same name.
const TITLES = [
  [/^\/$/, 'Dashboard'],
  [/^\/scan\/new/, 'New scan'],
  [/^\/scan\/[^/]+\/live/, 'Scan in progress'],
  [/^\/scans\/[^/]+\/report/, 'Scan report'],
  [/^\/scans\/[^/]+/, 'Scan results'],
  [/^\/scans/, 'Scan history'],
  [/^\/tools/, 'Tools'],
  [/^\/repos/, 'Repositories'],
];

function useDocumentTitle() {
  const { pathname } = useLocation();
  useEffect(() => {
    const match = TITLES.find(([pattern]) => pattern.test(pathname));
    document.title = match ? `${match[1]} · Security Orchestrator` : 'Security Orchestrator';
  }, [pathname]);
}

export default function App() {
  useDocumentTitle();

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<ScanForm />} />
        <Route path="/scan/:runId/live" element={<ScanLive />} />
        <Route path="/scans" element={<ScansList />} />
        <Route path="/scans/:runId" element={<ScanDetail />} />
        <Route path="/scans/:runId/report" element={<ScanReport />} />
        <Route path="/tools" element={<ToolsConfig />} />
        <Route path="/repos" element={<Repos />} />
      </Routes>
    </Layout>
  );
}
