import { useCallback, useEffect, useId, useRef } from 'react';
import { fmtLocation } from '../lib/format.js';
import { SeverityBadge, ScoreBar } from './Badges.jsx';

/* Finding detail modal (ported from showFindingModal in static/js/main.js).
   Rendered by ScanDetail; closes on overlay click, ✕, or Escape.

   Accessibility: the dialog is exposed with role="dialog" + aria-modal and is
   named by its heading, focus moves into it on open, is trapped while it is
   open, and returns to the element that opened it on close. Without that, a
   keyboard or screen-reader user could tab straight out of the dialog into the
   page behind it, with nothing announcing that a dialog had opened at all. */

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

/* Confidence, as scored rather than as reported.

   `confidence_effective` is written by the scoring pass: corroboration by a
   second tool lifts LOW to MEDIUM, which removes the low-confidence penalty.
   Showing only `confidence_raw`, as this modal did, left an analyst looking at
   a LOW finding whose score carried no penalty, with nothing on screen to
   explain the difference. The rule itself is deliberately NOT reimplemented
   here — the backend records the value it scored with, and this reads it. */
function Confidence({ finding }) {
  const raw = finding.confidence_raw;
  const effective = finding.confidence_effective;
  if (!raw) return '—';
  if (!effective || effective === raw) return raw;
  const n = (finding.corroborating_ids || []).length;
  return (
    <span>
      {raw} → {effective}{' '}
      <span className="muted">
        (corroborated by {n} other finding{n === 1 ? '' : 's'})
      </span>
    </span>
  );
}

function Field({ label, children }) {
  return (
    <div className="modal-field">
      <div className="modal-field-label">{label}</div>
      <div className="modal-field-value">{children}</div>
    </div>
  );
}

/* One of the two kinds of correlation link, or the untyped remainder.

   `hint` says what the link did to the score, because the two are not
   interchangeable: a shared product raises risk, a shared CVE raises
   confidence. The chips are real buttons — a span with onClick cannot be
   reached or activated from the keyboard. */
function RelatedField({ label, ids, hint, onJump }) {
  if (!ids.length) return null;
  return (
    <Field label={hint ? `${label} — ${hint}` : label}>
      {ids.map((id) => (
        <button key={id} type="button" className="related-chip" onClick={() => onJump(id)}>
          {id}
        </button>
      ))}
    </Field>
  );
}

export default function FindingModal({ finding, onClose, onJump }) {
  const boxRef = useRef(null);
  const closeRef = useRef(null);
  const openerRef = useRef(null);
  const titleId = useId();

  const open = Boolean(finding);

  // Remember what had focus, move focus into the dialog, and restore it on close.
  useEffect(() => {
    if (!open) return undefined;
    openerRef.current = document.activeElement;
    closeRef.current?.focus();
    return () => {
      if (openerRef.current instanceof HTMLElement) openerRef.current.focus();
    };
  }, [open]);

  const onKeyDown = useCallback(
    (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;

      const items = boxRef.current?.querySelectorAll(FOCUSABLE);
      if (!items || items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];

      // Wrap, so Tab cannot walk out of the dialog into the page behind it.
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose]
  );

  if (!open) return null;

  const loc = finding.location || {};
  const cves = (finding.cve || []).join(', ') || '—';
  const cwes = (finding.cwe || []).join(', ') || '—';
  // Deux natures de lien, et elles ne disent pas la même chose : l'une a pesé
  // sur le score, l'autre sur le crédit accordé au résultat. Les fondre en une
  // seule liste, comme avant, empêchait l'analyste de savoir laquelle a joué.
  const exposedVia = finding.risk_related_ids || [];
  const corroboratedBy = finding.corroborating_ids || [];
  const typed = new Set([...exposedVia, ...corroboratedBy]);
  const otherRelated = (finding.related_ids || []).filter((id) => !typed.has(id));
  const remediation = finding.llm_remediation || finding.remediation || null;
  const justification = finding.llm_justification || null;
  const references = finding.references || [];

  return (
    <div
      className="modal-overlay"
      style={{ display: 'flex' }}
      onKeyDown={onKeyDown}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-box" ref={boxRef} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <button ref={closeRef} className="modal-close" onClick={onClose} aria-label="Close finding details">
          <span aria-hidden="true">✕</span>
        </button>
        <div>
          <h2 id={titleId} style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>{finding.title}</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '.75rem', marginBottom: '1rem' }}>
            <Field label="ID"><code>{finding.id}</code></Field>
            <Field label="Severity"><SeverityBadge severity={finding.severity_raw} /></Field>
            <Field label="Risk Score"><ScoreBar score={finding.risk_score} /></Field>
            <Field label="Confidence"><Confidence finding={finding} /></Field>
            <Field label="Source">{finding.source || '—'}</Field>
            <Field label="Tool">{finding.tool || '—'}</Field>
            <Field label="Exposure">
              {finding.exposure ? finding.exposure.toUpperCase() : '—'}
            </Field>
          </div>
          <Field label="Location"><code>{fmtLocation(loc)}</code></Field>
          <Field label="Description">{finding.description || '—'}</Field>
          {finding.evidence && <Field label="Evidence"><code>{finding.evidence}</code></Field>}
          <Field label="CVE(s)">{cves}</Field>
          <Field label="CWE(s)">{cwes}</Field>
          <RelatedField
            label="Exposed Via"
            ids={exposedVia}
            hint="raises the risk score"
            onJump={onJump}
          />
          <RelatedField
            label="Corroborated By"
            ids={corroboratedBy}
            hint="raises confidence, not severity"
            onJump={onJump}
          />
          {otherRelated.length > 0 && (
            <RelatedField label="Related Findings" ids={otherRelated} onJump={onJump} />
          )}
          {remediation && <Field label="Remediation">{remediation}</Field>}
          {justification && <Field label="LLM Justification">{justification}</Field>}
          <Field label="References">
            {references.length
              ? references.map((r, i) => (
                  <span key={i}>
                    <a href={r} target="_blank" rel="noopener noreferrer">{r}</a>
                    {i < references.length - 1 && <br />}
                  </span>
                ))
              : '—'}
          </Field>
        </div>
      </div>
    </div>
  );
}
