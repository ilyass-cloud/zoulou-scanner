# Scénario de démonstration du moteur de scoring

Ce scénario étaye le §4.5 du mémoire. Il est **construit** : les jeux d'essai
ci-dessous ont été écrits pour l'occasion, et il ne faut pas le confondre avec
le scan réel du §6.3, qui portait sur le code du projet lui-même.

## Pourquoi il existe

Le scan du chapitre 6 analysait du code Python avec Bandit. Tous ses résultats
étaient d'exposition inconnue, de confiance haute et sans corrélation, de sorte
que chaque score se réduisait à la base de sévérité — 60 pour HIGH, 40 pour
MEDIUM, 20 pour LOW. Les trois termes qui distinguent la formule d'une simple
table de correspondance n'y étaient donc **jamais exercés**. Les tests unitaires
vérifient que le code implémente l'équation ; ils ne montrent pas qu'elle
priorise. Ce scénario le montre.

## Ce qu'il met en scène

Une application conteneurisée `myapp:2.4` déployée sur 10.0.0.1, dont le serveur
web nginx est exposé sur 80 et 443. Trois situations courantes s'y superposent :

1. **Le nginx de l'image porte une CVE, et ce même nginx est exposé.** Les deux
   faits sont distincts, et leur coexistence est pire que leur somme : c'est la
   règle 1 de corrélation, qui rehausse le risque (+5 par lien).
2. **`cryptography` est signalé deux fois** — par l'analyse de dépendances et
   par le scan d'image — sous la même CVE. Ce n'est pas un second fait, c'est le
   même vu deux fois : c'est la règle 2, qui relève la confiance et non le
   risque.
3. **Les services inventoriés sont en façade** (`default_exposure: external`),
   d'où le boost d'exposition de +15. À noter : seuls les résultats réseau
   portent une exposition ; un paquet vulnérable ne peut en bénéficier
   qu'indirectement, par la règle 1 — ce qui éclaire l'intérêt de cette règle.

Le résultat de dépendance sur `cryptography` est délibérément en confiance
`LOW`, et le secret l'est aussi. Les deux ont la même sévérité et la même
confiance brute ; seule la corroboration les sépare. C'est la démonstration la
plus nette de l'axe de la confiance, et rien d'autre ne la fournit.

## Ce qui a été écrit pour l'occasion, et pourquoi

Les jeux d'essai livrés dans `examples/` ne pouvaient déclencher ni l'une ni
l'autre règle : leurs produits réseau (`OpenSSH`, `nginx`, `MySQL`, `Redis`) ne
recoupent aucun de leurs paquets (`requests`, `pillow`, `cryptography`,
`openssl`, `libexpat1`), leurs cinq CVE sont toutes distinctes, et leur seul
résultat en confiance basse est un secret — or les secrets ne portent jamais de
CVE, donc ne peuvent être corroborés.

Il a donc fallu écrire : une entrée de conteneur nommée `nginx` (règle 1), et
une CVE citée par deux outils dont l'un en confiance basse (règle 2). Tout le
reste — la formule, les coefficients, le pipeline — est le code du projet, tel
quel.

## Exécution

```bash
./examples/demo_scoring/run.sh
```

Ni Docker, ni scanner installé, ni modèle de langage : les greffons lisent les
fichiers de ce répertoire, et `--network-input` met le greffon réseau en mode
sans exécution. Le résultat est strictement reproductible, et versionné dans
`out_demo_scoring/`.

`ranking.py` recalcule chaque terme depuis les champs du rapport et vérifie que
la décomposition retombe sur le score publié — le tableau produit est donc
vérifiable à la main, ligne à ligne.
