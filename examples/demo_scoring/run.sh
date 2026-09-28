#!/usr/bin/env bash
# Rejoue le scénario de démonstration du moteur de scoring (§4.5 du mémoire).
#
# Ni Docker, ni scanner installé, ni modèle de langage : les greffons lisent des
# sorties d'outils préenregistrées et --network-input met le greffon réseau en
# mode sans exécution. Le résultat est donc strictement reproductible.
#
# À lancer depuis la racine du dépôt : les chemins input_file de la
# configuration sont résolus par rapport au répertoire courant.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 -m orchestrator.main scan \
    --repo . \
    --config examples/demo_scoring/config.yaml \
    --out out_demo_scoring \
    --network-allowlist examples/allowlist.txt \
    --network-input examples/demo_scoring/nmap.xml \
    --no-llm "$@"

echo
python3 examples/demo_scoring/ranking.py
