# Épreuve sur des dépôts tiers (§6.6 du mémoire)

L'orchestrateur a été exécuté sur trois applications volontairement vulnérables,
avec de vrais scanners et sans modèle de langage (`--no-llm`). Ce dossier
contient les scripts de mesure et leurs résultats. Les sorties brutes des
scanners ne sont pas versionnées : elles sont volumineuses et contiennent les
secrets que ces applications exposent délibérément. Les commandes ci-dessous
les régénèrent.

## Cibles

| Dépôt | Commit | Pile |
|-------|--------|------|
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | `a1d8f89fac2e57093189853c6527c2b01fc1d9c1` | Python, aiohttp |
| [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | `19d17cc8874861142b330636d068bbde54e86b85` | Python, Django |
| [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | `1618a611b173b4bf114028e6e02549950606e29d` | Node.js, TypeScript |

Juice Shop ne versionne pas de `package-lock.json`. Il a été produit avec
`npm i --package-lock-only --ignore-scripts`, sans quoi npm audit ne peut rien lire.

## Outils

Semgrep 1.177.0, Bandit 1.9.4, pip-audit 2.10.1, npm 10.9.7 (npm audit),
Gitleaks 8.30.0, TruffleHog 3.93.7, Trivy 0.74.0.

Semgrep a tourné sur un jeu de règles communautaires figé, et non sur le
registre en ligne, qui n'était pas joignable : [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
au commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be`, répertoires
`python/{lang/security,django/security,flask/security,jwt,sqlalchemy}`,
`javascript/{express,lang/security,jsonwebtoken,sequelize}`, `generic/secrets`
et `dockerfile`. Ce jeu est passé par `SEMGREP_RULES`.

Trois outils n'ont pas pu être exécutés :
- Safety : sa version 3 exige un compte, et sa base libre n'était pas joignable ;
- Grype : sa base de vulnérabilités n'était pas téléchargeable ;
- Nmap : aucune cible réseau n'était autorisée.

Les convertisseurs de Safety et de Grype ne sont donc éprouvés que sur des
sorties construites d'après leur schéma documenté
(`tests/fixtures/native/*_constructed.json`).

## Reproduire

```bash
export SEMGREP_RULES=/chemin/vers/regles SEMGREP_SEND_METRICS=off
python -m orchestrator.main scan --repo <dépôt> --config config.demo.yaml --no-llm \
  --tools semgrep,bandit,pip-audit,gitleaks,trufflehog,trivy --out out_eval/<nom>
# Juice Shop : --tools semgrep,npm-audit,gitleaks,trufflehog,trivy

python examples/evaluation_tiers/analyse.py out_eval/*     > resultats.json
python examples/evaluation_tiers/avant_apres.py 836d786 out_eval/* > avant_apres.json
```

## Fichiers

- `avant_apres.json` soumet les mêmes sorties brutes au normaliseur d'avant la
  correction (commit `836d786`) et à celui d'après. L'écart mesure la seule
  normalisation.
- `resultats.json` rassemble, par dépôt :
  - les résultats par outil et par famille ;
  - les termes du score effectivement appliqués ;
  - le tau-b de Kendall entre le classement par sévérité seule et le classement par score ;
  - la sensibilité du top 20 à ±5 points sur chaque coefficient configurable ;
  - le top 10.

  La dernière entrée, `v2_zoulou_orch`, est le scan du §6.2 rejoué sur le code
  durci : Bandit et Semgrep sur `orchestrator/`.
