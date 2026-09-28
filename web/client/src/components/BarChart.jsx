import { useEffect, useRef } from 'react';
import { useTheme } from '../lib/theme.jsx';

/* Canvas bar chart with no external dependency – a direct port of the
   drawBarChart() routine from static/js/main.js. Redraws whenever the data,
   theme, or container size changes.

   Accessibility: a bare <canvas> exposes nothing at all — the bars, the counts,
   and the axis labels are pixels. The canvas is therefore given a role and a
   name summarising the data, and the same numbers are emitted as a real table
   for assistive technology, since a one-line label cannot convey a series. The
   table is visually hidden rather than absent, so the information is available
   without duplicating it on screen (WCAG 1.1.1). */
export default function BarChart({ labels, values, colors, height = 200, title = 'Bar chart' }) {
  const canvasRef = useRef(null);
  const { theme } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const draw = () => {
      const ctx = canvas.getContext('2d');
      const W = canvas.offsetWidth || 400;
      const H = canvas.offsetHeight || height;
      canvas.width = W;
      canvas.height = H;

      const cssVar = (name, fallback) =>
        getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;

      const max = Math.max(...values, 1);
      const barW = Math.floor((W - 60) / labels.length) - 8;
      const padL = 40, padB = 40, padT = 16;
      const chartH = H - padB - padT;

      ctx.clearRect(0, 0, W, H);

      // Y-axis gridlines
      ctx.strokeStyle = cssVar('--border', '#e2e8f0');
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = padT + chartH - (i / 4) * chartH;
        ctx.beginPath();
        ctx.moveTo(padL, y);
        ctx.lineTo(W - 8, y);
        ctx.stroke();
        ctx.fillStyle = cssVar('--text-muted', '#6b7280');
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round((i / 4) * max), padL - 4, y + 4);
      }

      labels.forEach((label, i) => {
        const x = padL + i * (barW + 8) + 4;
        const barH = values[i] ? (values[i] / max) * chartH : 0;
        const y = padT + chartH - barH;

        ctx.fillStyle = colors[i] || '#3b82f6';
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, y, barW, barH, [4, 4, 0, 0]);
        else ctx.rect(x, y, barW, barH);
        ctx.fill();

        if (values[i] > 0) {
          ctx.fillStyle = cssVar('--text', '#1e2330');
          ctx.font = 'bold 12px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(values[i], x + barW / 2, y - 4);
        }

        ctx.fillStyle = cssVar('--text-muted', '#6b7280');
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(label, x + barW / 2, H - 8);
      });
    };

    // Defer one frame so the canvas has its laid-out width.
    const raf = requestAnimationFrame(draw);
    window.addEventListener('resize', draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', draw);
    };
  }, [labels, values, colors, height, theme]);

  const summary = labels.map((l, i) => `${l}: ${values[i] ?? 0}`).join(', ');

  return (
    <>
      <canvas ref={canvasRef} height={height} role="img" aria-label={`${title}. ${summary}`} />
      <table className="visually-hidden">
        <caption>{title}</caption>
        <thead>
          <tr><th scope="col">Category</th><th scope="col">Count</th></tr>
        </thead>
        <tbody>
          {labels.map((label, i) => (
            <tr key={label}>
              <th scope="row">{label}</th>
              <td>{values[i] ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
