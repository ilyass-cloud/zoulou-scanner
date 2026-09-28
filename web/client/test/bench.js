/* Banc de mesure du rendu du journal temps réel — ancien chemin contre nouveau.
 *
 * Pourquoi il existe. Le §7.8 du mémoire oppose « le rendu est probablement
 * inefficace » à « 12,5 millions de rendus d'éléments pour cinq mille lignes,
 * 714 ms de calcul brut », et fait de cet écart un argument sur la valeur
 * probante de la mesure. Or les deux chiffres n'ont pas la même nature, et
 * aucun des deux n'était rejouable : le premier est un décompte fermé qui se
 * démontre (5000² / 2 = 12 500 000), le second une durée, qui ne se démontre
 * pas — elle s'observe, et aucun banc n'était versionné. Un argument sur la
 * valeur de la mesure ne peut pas reposer sur une mesure que personne ne peut
 * refaire.
 *
 * Ce que ce banc mesure honnêtement : le coût JavaScript pur — accumulation du
 * tableau et classification des lignes. C'est ce que l'audit annonçait
 * (« calcul brut, avant même la réconciliation »).
 *
 * Ce qu'il ne mesure PAS, et qu'il ne faut donc pas lui faire dire : le travail
 * de React et du DOM. La réconciliation et la pose des nœuds s'ajoutent à ces
 * durées dans un navigateur ; elles ne s'y substituent pas. Le décompte, lui,
 * vaut dans les deux cas : il ne dépend que de la forme du code.
 *
 * Volontairement nommé `bench.js` et non `*.test.js` : `npm test` exécute
 * `node --test test/*.test.js` et ne doit pas ramasser un banc, dont la durée
 * varie avec la machine et qui n'énonce aucune propriété à garder.
 *
 *   node web/client/test/bench.js            # 5000 lignes, lots de 50
 *   node web/client/test/bench.js 10000 100
 *   node web/client/test/bench.js --json     # relevé pour docs/log_bench.json
 */
import os from 'node:os';
import { appendCapped, lineClass, MAX_LOG_LINES } from '../src/lib/logs.js';

const args = process.argv.slice(2).filter((a) => a !== '--json');
const asJson = process.argv.includes('--json');
const LINES = Number(args[0] || 5000);
const BATCH = Number(args[1] || 50);

/** Lignes représentatives d'un scan verbeux : niveaux mêlés, longueurs réalistes. */
function makeLines(n) {
  const levels = ['[INFO]', '[DEBUG]', '[WARNING]', '[ERROR]', ''];
  const out = new Array(n);
  for (let i = 0; i < n; i += 1) {
    const level = levels[i % levels.length];
    out[i] = `2026-09-15 14:53:${String(i % 60).padStart(2, '0')} ${level} `
      + `plugin 'semgrep' scanning /srv/target/src/module_${i}/handler.py`;
  }
  return out;
}

/* Ancien chemin (commit 4c93fbc, ScanLive.jsx:33 et :170) :
 *   setLogs((cur) => [...cur, line])   — une copie du tableau par ligne
 *   logs.map((line) => …lineClass(line)…) — et un rendu complet par mise à jour
 * Sans plafond : le coût des deux croît avec le carré du nombre de lignes. */
function oldPath(lines) {
  let acc = [];
  let copies = 0;
  let classified = 0;
  let sink = 0;
  for (const line of lines) {
    acc = [...acc, line];
    copies += acc.length;
    for (let i = 0; i < acc.length; i += 1) {
      if (lineClass(acc[i]) !== '') sink += 1;
      classified += 1;
    }
  }
  return { copies, classified, sink, kept: acc.length };
}

/* Nouveau chemin : accumulation par trame via appendCapped, plafonnée, et un
 * rendu par trame et non par ligne. */
function newPath(lines, batchSize) {
  let acc = [];
  let copies = 0;
  let classified = 0;
  let sink = 0;
  for (let i = 0; i < lines.length; i += batchSize) {
    const batch = lines.slice(i, i + batchSize);
    const before = acc.length;
    acc = appendCapped(acc, batch);
    copies += before + batch.length;
    for (let j = 0; j < acc.length; j += 1) {
      if (lineClass(acc[j]) !== '') sink += 1;
      classified += 1;
    }
  }
  return { copies, classified, sink, kept: acc.length };
}

function time(fn, runs = 3) {
  fn(); // chauffe : sans elle on mesure surtout la compilation JIT
  const samples = [];
  for (let i = 0; i < runs; i += 1) {
    const t0 = performance.now();
    const result = fn();
    samples.push(performance.now() - t0);
    if (i === runs - 1) samples.result = result;
  }
  samples.sort((a, b) => a - b);
  return { ms: samples[Math.floor(samples.length / 2)], best: samples[0], result: samples.result };
}

const lines = makeLines(LINES);
const before = time(() => oldPath(lines));
const after = time(() => newPath(lines, BATCH));

const quadratic = (LINES * (LINES + 1)) / 2;
const report = {
  $comment: 'Produit par web/client/test/bench.js. Les décomptes sont exacts et '
    + 'ne dépendent pas de la machine ; les durées sont des observations sur '
    + 'celle nommée ci-dessous et ne valent que comme ordre de grandeur. '
    + 'Ni l\'une ni l\'autre ne mesure la réconciliation React ou le DOM.',
  lines: LINES,
  batch_size: BATCH,
  cap: MAX_LOG_LINES,
  environment: {
    runtime: `node ${process.version}`,
    platform: `${os.platform()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model ?? 'inconnu',
  },
  closed_form: {
    formula: 'n(n+1)/2',
    element_operations: quadratic,
    note: 'Décompte fermé de la somme quadratique : il découle de la forme du '
      + 'code et se démontre, il ne se mesure pas.',
  },
  before: {
    array_copies: before.result.copies,
    lines_classified: before.result.classified,
    lines_retained: before.result.kept,
    median_ms: Number(before.ms.toFixed(1)),
    best_ms: Number(before.best.toFixed(1)),
  },
  after: {
    array_copies: after.result.copies,
    lines_classified: after.result.classified,
    lines_retained: after.result.kept,
    median_ms: Number(after.ms.toFixed(1)),
    best_ms: Number(after.best.toFixed(1)),
  },
  speedup_median: Number((before.ms / after.ms).toFixed(1)),
};

if (asJson) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  const pad = (n) => String(n).padStart(12);
  console.log(`Journal temps réel — ${LINES} lignes, lots de ${BATCH}, plafond ${MAX_LOG_LINES}`);
  console.log(`  ${report.environment.runtime} · ${report.environment.platform}`);
  console.log('');
  console.log('                        avant          après');
  console.log(`  copies d'éléments ${pad(report.before.array_copies)}  ${pad(report.after.array_copies)}`);
  console.log(`  lignes classées   ${pad(report.before.lines_classified)}  ${pad(report.after.lines_classified)}`);
  console.log(`  lignes conservées ${pad(report.before.lines_retained)}  ${pad(report.after.lines_retained)}`);
  console.log(`  durée médiane     ${pad(`${report.before.median_ms} ms`)}  ${pad(`${report.after.median_ms} ms`)}`);
  console.log('');
  console.log(`  n(n+1)/2 = ${quadratic} — décompte fermé, non mesuré`);
  console.log(`  rapport des durées : ×${report.speedup_median}`);
  console.log('');
  console.log('  Réconciliation React et DOM non mesurés : ils s\'ajoutent à ces');
  console.log('  durées dans un navigateur, ils ne s\'y substituent pas.');
}
