#!/usr/bin/env bash
# Relève le nombre de cas de test des trois suites et écrit docs/test_counts.json.
#
# Pourquoi un script et non un test : un test qui compterait les tests serait
# circulaire et casserait à chaque ajout. Un relevé versionné, que la CI compare
# à l'état du dépôt, place l'obligation au bon endroit : celui qui ajoute un
# test relance le relevé, et les documents citent ce fichier au lieu d'une
# valeur recopiée à la main.
#
#   ./scripts/count_tests.sh          # écrit docs/test_counts.json
#   ./scripts/count_tests.sh --check  # échoue si le fichier est périmé
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=docs/test_counts.json

python_count=$(python3 -m pytest tests/ -q --collect-only 2>/dev/null \
    | grep -oE '^[0-9]+ tests? collected' | grep -oE '^[0-9]+')

node_count=$(cd web/server && npm test 2>/dev/null | grep -oE '^# tests [0-9]+' | grep -oE '[0-9]+$')
react_count=$(cd web/client && npm test 2>/dev/null | grep -oE '^# tests [0-9]+' | grep -oE '[0-9]+$')

for name in python_count node_count react_count; do
    value="${!name}"
    if [ -z "$value" ]; then
        echo "erreur : $name n'a pas pu être relevé — suite non exécutable ?" >&2
        exit 1
    fi
done

total=$((python_count + node_count + react_count))

tmp=$(mktemp)
cat > "$tmp" <<JSON
{
  "\$comment": "Relevé par scripts/count_tests.sh. Ne pas éditer à la main : la CI vérifie qu’il correspond au dépôt.",
  "python": $python_count,
  "node": $node_count,
  "react": $react_count,
  "total": $total
}
JSON

if [ "${1:-}" = "--check" ]; then
    if ! diff -q "$OUT" "$tmp" >/dev/null 2>&1; then
        echo "docs/test_counts.json est périmé. Attendu :" >&2
        diff "$OUT" "$tmp" >&2 || true
        echo "Relancer ./scripts/count_tests.sh et committer le résultat." >&2
        rm -f "$tmp"
        exit 1
    fi
    rm -f "$tmp"
    echo "[OK] docs/test_counts.json est à jour ($total cas)"
    exit 0
fi

mv "$tmp" "$OUT"
chmod 644 "$OUT"
echo "[OK] $OUT — python=$python_count node=$node_count react=$react_count total=$total"
