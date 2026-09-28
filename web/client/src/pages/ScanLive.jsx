import { memo, useEffect, useRef, useState, useCallback } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { appendCapped, applyPluginProgress, lineClass, MAX_LOG_LINES } from '../lib/logs.js';

const PLUGIN_NAMES = ['sast', 'deps', 'secrets', 'container', 'network'];

const STATE_ICON = { running: '⚙️', done: '✅', error: '❌', waiting: '⏳' };

// Memoised so a flush only reconciles the lines it actually added. Without
// this, every batch re-rendered every line already on screen.
const LogLine = memo(function LogLine({ text, cls }) {
  return <div className={cls}>{text}</div>;
});

export default function ScanLive() {
  const { runId } = useParams();
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('running');
  const [findingCount, setFindingCount] = useState(null);
  const [autoscroll, setAutoscroll] = useState(true);
  const [plugins, setPlugins] = useState(() =>
    Object.fromEntries(PLUGIN_NAMES.map((p) => [p, 'waiting']))
  );

  const [received, setReceived] = useState(0);

  const logContainerRef = useRef(null);
  const esRef = useRef(null);
  const pollRef = useRef(null);
  const autoscrollRef = useRef(autoscroll);
  autoscrollRef.current = autoscroll;

  // Incoming lines are buffered and flushed once per animation frame. The
  // previous code called setLogs once per line with `[...cur, line]`, which is
  // quadratic — 5000 lines meant 5000 renders copying an ever-growing array and
  // re-mapping every line to a DOM node, ~12.5M element renders in total. A
  // verbose scanner locked up the tab.
  const bufferRef = useRef([]);
  const frameRef = useRef(null);
  const nextIdRef = useRef(0);

  const flush = useCallback(() => {
    frameRef.current = null;
    const batch = bufferRef.current;
    if (!batch.length) return;
    bufferRef.current = [];

    setLogs((cur) => appendCapped(cur, batch));
    setPlugins((cur) => applyPluginProgress(cur, batch));
    setReceived(nextIdRef.current);
  }, []);

  const appendLog = useCallback((line) => {
    bufferRef.current.push({ id: nextIdRef.current++, text: line, cls: lineClass(line) });
    // A backgrounded tab gets no animation frames, so bound the buffer too;
    // otherwise it would grow without limit while nothing is being painted.
    if (bufferRef.current.length > MAX_LOG_LINES) {
      bufferRef.current.splice(0, bufferRef.current.length - MAX_LOG_LINES);
    }
    if (frameRef.current == null) {
      frameRef.current = requestAnimationFrame(flush);
    }
  }, [flush]);

  useEffect(() => () => {
    if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
  }, []);

  const clearLogs = useCallback(() => {
    bufferRef.current = [];
    nextIdRef.current = 0;
    setLogs([]);
    setReceived(0);
  }, []);

  const onDone = useCallback(
    (finalStatus) => {
      setStatus(finalStatus);
      api
        .getScan(runId)
        .then((d) => {
          if (d.finding_count != null) setFindingCount(d.finding_count);
        })
        .catch(() => {});
    },
    [runId]
  );

  useEffect(() => {
    const es = new EventSource(`/api/scans/${runId}/logs`);
    esRef.current = es;

    es.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.heartbeat) return;
      if (msg.done) {
        es.close();
        onDone(msg.status);
        return;
      }
      if (msg.line) appendLog(msg.line);
    };

    es.onerror = () => {
      appendLog('[SSE connection lost – polling for status…]');
      es.close();
      pollRef.current = setInterval(async () => {
        try {
          const data = await api.getScan(runId);
          if (['done', 'error', 'cancelled'].includes(data.status)) {
            clearInterval(pollRef.current);
            onDone(data.status);
          }
        } catch {
          /* ignore */
        }
      }, 3000);
    };

    return () => {
      es.close();
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [runId, appendLog, onDone]);

  // Auto-scroll to bottom as logs grow.
  useEffect(() => {
    if (autoscrollRef.current && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const cancelScan = async () => {
    if (!confirm('Cancel this scan?')) return;
    try {
      await api.cancelScan(runId);
      appendLog('[User requested cancellation]');
    } catch (e) {
      appendLog(`[Cancel failed: ${e.message}]`);
    }
  };

  const done = ['done', 'error', 'cancelled'].includes(status);
  const doneIcon = status === 'done' ? '✅' : status === 'error' ? '❌' : '⛔';
  const doneMsg = status === 'done' ? 'Scan complete' : status === 'error' ? 'Scan failed' : 'Scan cancelled';

  return (
    <>
      {/* The one thing worth interrupting a screen-reader user for: the scan
          finishing, or a plugin changing state. Low-frequency, unlike the log. */}
      <div aria-live="polite" className="visually-hidden">
        {done
          ? `${doneMsg}${findingCount != null ? `, ${findingCount} findings` : ''}`
          : `Scan running. ${PLUGIN_NAMES.map((p) => `${p} ${plugins[p]}`).join(', ')}`}
      </div>

      <div className="page-header">
        <h1>Scan <code>{runId}</code></h1>
        <div className="header-actions">
          <span className={`badge badge-${status}`}>{status}</span>
          {!done && (
            <button className="btn btn-danger" onClick={cancelScan}>⛔ Cancel</button>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header"><h2>Plugin Progress</h2></div>
        <div className="card-body">
          <div className="plugin-progress-list">
            {PLUGIN_NAMES.map((p) => {
              const state = plugins[p];
              return (
                <div key={p} className={`plugin-progress-item pp-${state}`}>
                  <span className="pp-icon">{STATE_ICON[state] || '⏳'}</span>
                  <span className="pp-name">{p.toUpperCase()}</span>
                  <span className="pp-status">{state}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Live Log</h2>
          <div className="header-actions">
            <label className="toggle-label-sm">
              <input
                type="checkbox"
                checked={autoscroll}
                onChange={(e) => setAutoscroll(e.target.checked)}
              />{' '}
              Auto-scroll
            </label>
            <button className="btn btn-sm" onClick={clearLogs}>Clear</button>
          </div>
        </div>
        <div className="card-body p-0">
          {/* tabIndex makes the scrollable region reachable by keyboard (2.1.1).
              It is deliberately NOT an aria-live region: announcing thousands of
              scanner lines would make the page unusable with a screen reader.
              Scan status is announced separately, below. */}
          <div
            className="log-container"
            ref={logContainerRef}
            tabIndex={0}
            role="log"
            aria-label="Scanner output"
          >
            <div className="log-output">
              {received > logs.length && (
                <div className="log-line-info">
                  […{received - logs.length} earlier line(s) hidden – showing the most recent {MAX_LOG_LINES}]
                </div>
              )}
              {logs.map((entry) => (
                <LogLine key={entry.id} text={entry.text} cls={entry.cls} />
              ))}
            </div>
          </div>
        </div>
      </div>

      {done && (
        <div className="card done-panel">
          <div className="card-body done-body">
            <div className="done-icon">{doneIcon}</div>
            <div className="done-message">{doneMsg}</div>
            <div className="done-count">
              {findingCount != null ? `${findingCount} finding(s) found` : ''}
            </div>
            <div className="done-actions">
              <Link to={`/scans/${runId}`} className="btn btn-primary btn-lg">View Results</Link>
              <Link to="/scan/new" className="btn btn-secondary btn-lg">New Scan</Link>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
