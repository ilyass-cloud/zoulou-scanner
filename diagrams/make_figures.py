# -*- coding: utf-8 -*-
"""
Figures d'architecture du projet — SVG tracés à la main.

La mise en page automatique (Mermaid) est ce qui avait produit des figures
étirées, aux flèches croisées et aux étiquettes tronquées ; chaque élément est
donc placé explicitement. Les trois figures partagent une palette sobre : encre
foncée, teintes claires par zone, un seul gris pour les flèches.

Les tailles de police sont choisies pour la largeur d'impression (14,82 cm) :
à cette échelle, une police de 19 px sur un canevas de 1000 px vaut ≈ 8 pt.

Rendu PNG (1750 px de large) : les SVG sont rastérisés par Chromium, par
exemple avec Playwright (page.setContent du SVG, deviceScaleFactor = 1750 / largeur).

Conventions graphiques (rappelées dans une légende) :
  trait plein   — appel ou flux de données
  trait tireté  — échange par fichier (IPC), cf. §4.8.2
"""
from pathlib import Path

OUT = Path(__file__).parent

INK, MUTED, EDGE = "#1f2937", "#6b7280", "#4b5563"
FONT = "Liberation Sans, Helvetica, Arial, sans-serif"

Z_UI   = ("#eef6ee", "#3a7d44")   # interface
Z_CORE = ("#e8f0fe", "#2f5aa8")   # cœur déterministe
Z_EXEC = ("#fdf0e6", "#c2612e")   # exécuteur / conteneur éphémère
Z_LLM  = ("#f3ecf9", "#7c4dad")   # couche probabiliste
Z_STO  = ("#f4f4f5", "#52525b")   # persistance, fichiers, sorties
Z_HOST = ("#fafafa", "#9ca3af")   # nœud hôte
WHITE  = ("#ffffff", INK)


# ── Primitives ────────────────────────────────────────────────────────────
class Svg:
    def __init__(self, w, h):
        self.w, self.h, self.parts = w, h, []

    def add(self, s):
        self.parts.append(s)

    def zone(self, x, y, w, h, title, tint, dashed=False, title_size=19, title_anchor="start"):
        fill, stroke = tint
        dash = ' stroke-dasharray="8 6"' if dashed else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>')
        tx = x + w / 2 if title_anchor == "middle" else x + 16
        self.text(tx, y + 26, title, size=title_size, color=stroke, bold=True, anchor=title_anchor)

    def _lines(self, cx, cy, lines, size, bold_first, sub_size, sub_color, first_color=INK):
        sub_size = sub_size or round(size * 0.82)
        sizes = [size] + [sub_size] * (len(lines) - 1)
        gap = 6
        total = sum(sizes) + gap * (len(lines) - 1)
        y = cy - total / 2
        for i, (ln, sz) in enumerate(zip(lines, sizes)):
            y += sz
            bold = ' font-weight="bold"' if (i == 0 and bold_first) else ""
            color = first_color if i == 0 else sub_color
            self.add(f'<text x="{cx}" y="{y - sz*0.18}" font-family="{FONT}" font-size="{sz}"'
                     f'{bold} fill="{color}" text-anchor="middle">{ln}</text>')
            y += gap

    def box(self, x, y, w, h, lines, tint=WHITE, size=19, bold_first=True,
            sub_size=None, sub_color=MUTED, stroke_w=1.6, rx=8, dx=0, dy=0):
        fill, stroke = tint
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_w}"/>')
        self._lines(x + w / 2 + dx, y + h / 2 + dy, lines, size, bold_first, sub_size, sub_color)

    def cylinder(self, x, y, w, h, lines, tint=Z_STO, size=18, sub_size=None):
        fill, stroke = tint
        ry = 11
        self.add(f'<path d="M{x},{y+ry} a{w/2},{ry} 0 0 1 {w},0 v{h-2*ry} '
                 f'a{w/2},{ry} 0 0 1 -{w},0 z" fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
        self.add(f'<ellipse cx="{x+w/2}" cy="{y+ry}" rx="{w/2}" ry="{ry}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
        self._lines(x + w / 2, y + h / 2 + 6, lines, size, True, sub_size, MUTED)

    def file(self, x, y, w, h, lines, size=16):
        """Nœud « fichier » : rectangle à coin plié."""
        fill, stroke = Z_STO
        f = 12
        self.add(f'<path d="M{x},{y} h{w-f} l{f},{f} v{h-f} h-{w} z" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="1.6"/>')
        self.add(f'<path d="M{x+w-f},{y} v{f} h{f}" fill="none" stroke="{stroke}" stroke-width="1.4"/>')
        if isinstance(lines, str):
            lines = [lines]
        self._lines(x + w / 2, y + h / 2, lines, size, False, None, MUTED, first_color=INK)

    def edge(self, pts, dashed=False, label=None, label_at=None, arrow=True, both=False, lsize=15):
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        dash = ' stroke-dasharray="9 7"' if dashed else ""
        mk = ' marker-end="url(#arr)"' if arrow else ""
        ms = ' marker-start="url(#arrs)"' if both else ""
        self.add(f'<path d="{d}" fill="none" stroke="{EDGE}" stroke-width="1.8"{dash}{mk}{ms}/>')
        if label:
            if label_at is None:
                (x1, y1), (x2, y2) = pts[0], pts[-1]
                label_at = ((x1 + x2) / 2, (y1 + y2) / 2)
            self.label(*label_at, label, size=lsize)

    def label(self, x, y, text, size=15, color=MUTED):
        w = len(text) * size * 0.56 + 12
        self.add(f'<rect x="{x-w/2}" y="{y-size*0.75}" width="{w}" height="{size*1.5}" rx="4" '
                 f'fill="#ffffff" fill-opacity="0.95"/>')
        self.add(f'<text x="{x}" y="{y+size*0.35}" font-family="{FONT}" font-size="{size}" '
                 f'fill="{color}" text-anchor="middle">{text}</text>')

    def text(self, x, y, s, size=16, color=INK, bold=False, anchor="start"):
        b = ' font-weight="bold"' if bold else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}"{b} '
                 f'fill="{color}" text-anchor="{anchor}">{s}</text>')

    def legend(self, x, y, items, size=15):
        cx = x
        for kind, txt in items:
            if kind == "solid":
                self.add(f'<path d="M{cx},{y} h34" stroke="{EDGE}" stroke-width="1.8" marker-end="url(#arr)"/>')
            elif kind == "dashed":
                self.add(f'<path d="M{cx},{y} h34" stroke="{EDGE}" stroke-width="1.8" '
                         f'stroke-dasharray="9 7" marker-end="url(#arr)"/>')
            else:
                fill, stroke = kind
                self.add(f'<rect x="{cx}" y="{y-9}" width="34" height="18" rx="3" fill="{fill}" '
                         f'stroke="{stroke}" stroke-width="1.4"/>')
            self.text(cx + 44, y + 5, txt, size=size, color=MUTED)
            cx += 44 + len(txt) * size * 0.56 + 34

    def render(self):
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                f'viewBox="0 0 {self.w} {self.h}">'
                f'<defs>'
                f'<marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
                f'markerHeight="8" orient="auto-start-reverse">'
                f'<path d="M0,0 L10,5 L0,10 z" fill="{EDGE}"/></marker>'
                f'<marker id="arrs" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="8" '
                f'markerHeight="8" orient="auto-start-reverse">'
                f'<path d="M10,0 L0,5 L10,10 z" fill="{EDGE}"/></marker>'
                f'</defs>'
                f'<rect width="100%" height="100%" fill="#ffffff"/>')
        return head + "".join(self.parts) + "</svg>"


# ══════════════════════════════════════════════════════════════════════════
# Figure 4.1 — Architecture générale
# ══════════════════════════════════════════════════════════════════════════
def fig_4_1():
    s = Svg(1400, 910)

    # Zones
    s.zone(40, 40, 980, 175, "Interface", Z_UI)
    s.zone(1060, 40, 300, 525, "Persistance et sorties", Z_STO)
    s.zone(40, 250, 980, 315, "Cerveau — orchestrateur (Python)", Z_CORE)
    s.zone(550, 285, 460, 125, "Analyse par modèle de langage (local)", Z_LLM, title_size=17)
    s.zone(40, 620, 1330, 230, "Exécuteur — conteneur Docker éphémère (une instance par scan)", Z_EXEC)

    # Interface
    s.box(70, 100, 150, 70, ["Analyste", "navigateur"])
    s.box(280, 100, 240, 70, ["Frontend React / Vite", "application monopage"])
    s.box(560, 100, 280, 70, ["Backend Node / Express", "REST + SSE temps réel"])
    s.box(880, 100, 120, 70, ["CLI", "main.py"])
    s.edge([(220, 135), (280, 135)])
    s.edge([(520, 135), (560, 135)])

    # Persistance et sorties
    s.cylinder(1130, 112, 160, 88, ["PostgreSQL", "scans · utilisateurs · clés"], size=17, sub_size=13)
    s.file(1080, 290, 100, 56, "report.json")
    s.file(1080, 360, 100, 56, "report.md")
    s.box(1100, 430, 200, 58, ["Tableau de bord web"], size=17)
    s.edge([(800, 170), (800, 192), (1130, 192)], label="persistance", label_at=(950, 192))
    s.edge([(1210, 200), (1210, 430)], label="lecture", label_at=(1240, 315))

    # Cerveau — colonne de planification (gauche)
    s.box(60, 288, 200, 54, ["Détection", "d'environnement"], size=16, sub_color=INK, sub_size=16)
    s.box(60, 372, 200, 54, ["Planification", "registre d'outils"], size=17)
    s.edge([(160, 342), (160, 372)])
    # Bus interface → planification (goulotte entre les bandes)
    s.edge([(940, 170), (940, 230)], arrow=False)
    s.edge([(700, 170), (700, 230)], arrow=False)
    # L'appel entre dans le cerveau par sa bordure : la flèche s'arrête sur la
    # zone, faute de quoi elle traverserait son titre.
    s.edge([(940, 230), (160, 230), (160, 250)], label="lance un scan", label_at=(430, 230))

    # Cerveau — chaîne de traitement
    s.box(300, 455, 160, 64, ["Normalisation", "→ Finding[]"], size=17)
    s.box(490, 455, 150, 64, ["Corrélation", "empreinte, liens"], size=17)
    s.box(670, 455, 140, 64, ["Scoring", "risque 0–100"], size=17)
    s.box(880, 455, 120, 64, ["Rapports", "génération"], size=17)
    s.edge([(460, 487), (490, 487)])
    s.edge([(640, 487), (670, 487)])
    s.edge([(810, 487), (880, 487)])

    # LLM
    s.box(575, 318, 150, 58, ["Client LM Studio"], size=15)
    s.box(745, 318, 110, 58, ["Synthèse", "exécutive"], size=15)
    s.box(875, 318, 120, 58, ["Triage et", "remédiation"], size=15)
    s.edge([(725, 347), (745, 347)])
    s.edge([(855, 347), (875, 347)])
    s.edge([(740, 455), (650, 376)], label="top résultats", label_at=(655, 428))
    s.edge([(800, 376), (905, 455)])
    s.edge([(935, 376), (945, 455)])

    # Rapports → sorties
    s.edge([(1000, 487), (1050, 487), (1050, 318), (1080, 318)])
    s.edge([(1050, 388), (1080, 388)])
    s.edge([(1050, 459), (1100, 459)])

    # Exécuteur
    s.box(60, 700, 200, 64, ["Runner", "sous-commande run-plan"], size=17)
    stroke = Z_EXEC[1]
    s.add(f'<rect x="280" y="662" width="945" height="135" rx="8" fill="#ffffff" '
          f'stroke="{stroke}" stroke-width="1.4" stroke-dasharray="6 5"/>')
    s.text(296, 684, "Greffons de scan (registre d'outils)", size=15, color=stroke, bold=True)
    gx = 300
    for w, lines in [(180, ["SAST", "Semgrep · Bandit"]),
                     (185, ["Dépendances", "pip-audit · npm audit"]),
                     (175, ["Secrets", "Gitleaks · TruffleHog"]),
                     (165, ["Conteneurs", "Trivy · Grype"]),
                     (140, ["Réseau", "Nmap, sur autorisation"])]:
        s.box(gx, 700, w, 76, lines, tint=Z_EXEC, size=17, sub_size=13)
        gx += w + 15
    s.edge([(260, 732), (280, 732)])
    s.file(1255, 710, 90, 46, "artifacts.json", size=14)
    s.edge([(1225, 732), (1255, 732)])

    # IPC par fichiers (tirets)
    s.edge([(160, 426), (160, 700)], dashed=True, label="plan.json", label_at=(160, 592))
    s.edge([(1300, 710), (1300, 592), (380, 592), (380, 519)], dashed=True,
           label="artifacts.json", label_at=(845, 592))

    # Légende
    s.legend(56, 880, [("solid", "appel ou flux de données"),
                       ("dashed", "échange par fichier (IPC)"),
                       (Z_CORE, "cœur déterministe"),
                       (Z_LLM, "couche probabiliste")])
    return s.render()


# ══════════════════════════════════════════════════════════════════════════
# Figure 4.2 — Le pipeline de traitement (disposition verticale)
# ══════════════════════════════════════════════════════════════════════════
def fig_4_2():
    s = Svg(1000, 880)
    BX, BW, BH, GAP, Y0 = 280, 440, 74, 22, 130
    CX = BX + BW / 2

    steps = [
        ("Planification",              "détection d'environnement · greffons",   Z_CORE, "plan.json"),
        ("Exécution des greffons",     "conteneur éphémère par scan",            Z_CORE, "artifacts.json"),
        ("Normalisation",              "sorties hétérogènes → modèle Finding",   Z_CORE, "objets Finding"),
        ("Déduplication, corrélation", "empreinte SHA-256 · related_ids",        Z_CORE, "related_ids"),
        ("Scoring",                    "risque déterministe, échelle 0–100",     Z_CORE, "risk_score"),
        ("Analyse par LLM local",      "sortie structurée · ancrée sur la preuve", Z_LLM, "synthèse, remédiations"),
        ("Génération des rapports",    "JSON, Markdown, tableau de bord",        Z_STO,  "report.json · report.md"),
    ]

    # Entrée
    s.cylinder(400, 28, 200, 72, ["Dépôt source"], size=22)
    s.edge([(500, 100), (500, Y0)])

    ys = []
    for i, (title, sub, tint, product) in enumerate(steps):
        y = Y0 + i * (BH + GAP)
        ys.append(y)
        s.box(BX, y, BW, BH, [title, sub], tint=tint, size=25, sub_size=18, dx=14)
        # badge numéroté
        s.add(f'<circle cx="{BX+24}" cy="{y+BH/2}" r="16" fill="{tint[1]}"/>')
        s.text(BX + 24, y + BH / 2 + 6, str(i + 1), size=18, color="#ffffff", bold=True, anchor="middle")
        # produit de l'étape, à droite
        s.edge([(BX + BW, y + BH / 2), (760, y + BH / 2)])
        s.file(760, y + BH / 2 - 24, 210, 48, product, size=16)
        if i < len(steps) - 1:
            s.edge([(CX, y + BH), (CX, y + BH + GAP)])

    # Barres de zone (à gauche) et leurs libellés
    def bar(y1, y2, tint, lines):
        s.add(f'<rect x="250" y="{y1}" width="7" height="{y2-y1}" rx="3" fill="{tint[1]}"/>')
        s._lines(145, (y1 + y2) / 2, lines, 19, True, 17, MUTED, first_color=tint[1])
    bar(ys[0], ys[4] + BH, Z_CORE, ["Cœur déterministe", "reproductible", "et testable"])
    bar(ys[5], ys[5] + BH, Z_LLM, ["Couche probabiliste", "encadrée par la", "règle d'ancrage"])
    bar(ys[6], ys[6] + BH, Z_STO, ["Sorties"])

    s.legend(44, 850, [("solid", "flux de traitement"),
                       (Z_CORE, "étape déterministe"),
                       (Z_LLM, "étape probabiliste"),
                       (Z_STO, "artefact produit")])
    return s.render()


# ══════════════════════════════════════════════════════════════════════════
# Figure 4.5 — Diagramme de déploiement
# ══════════════════════════════════════════════════════════════════════════
def fig_4_5():
    s = Svg(1200, 1040)

    s.box(95, 40, 320, 82, ["«device» Poste de l'analyste", "navigateur web"], size=19)

    # Titre centré : la liaison HTTPS descend sur la gauche de la zone.
    s.zone(60, 180, 1100, 810, "«node» Hôte — infrastructure maîtrisée", Z_HOST, title_anchor="middle")
    s.text(610, 228, "socket Docker monté dans le conteneur cerveau ; LM Studio joignable via host.docker.internal",
           size=14, color=MUTED, anchor="middle")

    # Conteneur cerveau
    s.zone(110, 250, 810, 190, "«container» Cerveau — web et orchestration", Z_CORE, title_size=18)
    s.box(130, 310, 230, 90, ["SPA React / Vite", "servie en statique"], size=18)
    s.box(400, 310, 240, 90, ["Backend Node / Express", "API, SSE, docker run"], size=17)
    s.box(680, 310, 210, 90, ["Orchestrateur Python", "plan · normalize · score · report"], size=17, sub_size=13)
    s.edge([(360, 355), (400, 355)], label="REST + SSE", label_at=(355, 422))
    s.edge([(640, 355), (680, 355)], label="sous-processus CLI", label_at=(660, 422))
    s.edge([(255, 122), (255, 310)], label="HTTPS", label_at=(255, 150))

    # LM Studio (sur l'hôte)
    s.box(950, 270, 190, 170, ["«device»", "Serveur d'inférence", "LLM local", "LM Studio",
                               "API compatible OpenAI", "/v1/chat/completions"],
          tint=Z_LLM, size=16, sub_size=15, sub_color=INK, bold_first=False)
    s.edge([(890, 355), (950, 355)], label="HTTP", label_at=(920, 333), lsize=14)

    # Persistance
    s.cylinder(450, 530, 180, 100, ["PostgreSQL", "«database»"], size=18)
    s.edge([(540, 400), (540, 530)], label="persistance des scans", label_at=(540, 470))

    # Volume partagé
    s.cylinder(685, 530, 200, 100, ["Volume partagé", "«artifact»", "plan.json · artifacts.json"], size=16, sub_size=13)
    s.edge([(785, 400), (785, 530)], both=True, label="écrit plan.json · lit artifacts.json",
           label_at=(785, 470), lsize=14)

    # Exécuteur éphémère
    s.zone(110, 740, 810, 210, "«container, éphémère» Exécuteur — une instance par scan", Z_EXEC, title_size=18)
    s.box(150, 800, 730, 110, ["Runner (run-plan) et scanners",
                               "Semgrep · Bandit · pip-audit · Gitleaks · TruffleHog · Trivy · Grype · Nmap",
                               "dépôt cible monté en lecture seule"],
          tint=Z_EXEC, size=18, sub_size=14)
    s.edge([(430, 400), (430, 740)], label="docker run (cycle de vie)", label_at=(430, 680))
    s.edge([(785, 630), (785, 800)], both=True, dashed=True,
           label="lit plan.json · écrit artifacts.json", label_at=(785, 700), lsize=14)

    s.legend(76, 1015, [("solid", "communication réseau ou appel"),
                        ("dashed", "échange par fichier (IPC)"),
                        (Z_EXEC, "conteneur éphémère")])
    return s.render()


# ══════════════════════════════════════════════════════════════════════════
# Figure 4.3 — Diagramme de classes (extrait)
#
# Le rendu Mermaid alignait quinze classes sur une seule rangée : réduit à la
# largeur de la page, le texte devenait illisible. Seules les classes que le
# chapitre 4 commente sont reprises, avec leurs attributs essentiels.
# ══════════════════════════════════════════════════════════════════════════
LINE_H = 25


def uml(s, x, y, w, name, attrs=(), methods=(), stereo=None, tint=Z_CORE, size=18):
    """Classe UML : en-tête (stéréotype, nom), attributs, opérations. Renvoie sa hauteur."""
    fill, stroke = tint
    head = 44 + (22 if stereo else 0)
    h_attr = (len(attrs) * LINE_H + 14) if attrs else 0
    h_meth = (len(methods) * LINE_H + 14) if methods else 0
    h = head + h_attr + h_meth
    s.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" fill="#ffffff" '
          f'stroke="{stroke}" stroke-width="1.8"/>')
    s.add(f'<rect x="{x}" y="{y}" width="{w}" height="{head}" rx="4" fill="{fill}" '
          f'stroke="{stroke}" stroke-width="1.8"/>')
    ty = y + 29
    if stereo:
        s.add(f'<text x="{x + w/2}" y="{y + 24}" font-family="{FONT}" font-size="{size - 3}" '
              f'font-style="italic" fill="{MUTED}" text-anchor="middle">«{stereo}»</text>')
        ty += 20
    s.text(x + w / 2, ty, name, size=size + 2, bold=True, anchor="middle",
           color=stroke if stereo == "abstract" else INK)
    cy = y + head
    for group in (attrs, methods):
        if not group:
            continue
        s.add(f'<path d="M{x},{cy} h{w}" stroke="{stroke}" stroke-width="1.2"/>')
        yy = cy + 7
        for a in group:
            yy += LINE_H
            s.text(x + 12, yy - 6, a, size=size)
        cy += len(group) * LINE_H + 14
    return h


def inherit(s, parent_x, parent_y, children, bus_y):
    """Généralisation : triangle creux sous le parent, bus horizontal, descentes."""
    s.add(f'<path d="M{parent_x},{parent_y} l-11,20 h22 z" fill="#ffffff" stroke="{EDGE}" stroke-width="1.8"/>')
    s.add(f'<path d="M{parent_x},{parent_y + 20} V{bus_y}" stroke="{EDGE}" stroke-width="1.8"/>')
    xs = [c[0] for c in children]
    s.add(f'<path d="M{min(xs + [parent_x])},{bus_y} H{max(xs + [parent_x])}" stroke="{EDGE}" stroke-width="1.8"/>')
    for cx, cy in children:
        s.add(f'<path d="M{cx},{bus_y} V{cy}" stroke="{EDGE}" stroke-width="1.8"/>')


def fig_4_3():
    s = Svg(1200, 1010)
    C, X = Z_CORE, Z_EXEC

    # Greffons
    h_base = uml(s, 200, 30, 360, "BasePlugin", ["name : str", "scan_type : ScanType"],
                 ["run(context) : RawScanArtifact"], stereo="abstract", tint=X)
    h_live = uml(s, 30, 270, 250, "LivePlugin", ["tool_def : ToolDefinition"],
                 ["is_installed() : bool", "run(context)"], tint=X)
    uml(s, 300, 270, 200, "NetworkPlugin", ["name = network"], ["run(context)"], tint=X)
    uml(s, 520, 270, 230, "Greffons de démo", ["sast · deps", "secrets · container"], tint=X)
    inherit(s, 380, 30 + h_base, [(155, 270), (400, 270), (635, 270)], 240)

    uml(s, 30, 470, 250, "ToolDefinition", ["name : str", "category : str",
                                             "command : str", "output_format : str"], tint=X)
    s.add(f'<path d="M155,{270 + h_live} V470" stroke="{EDGE}" stroke-width="1.8"/>')
    s.text(165, 452, "1", size=16, color=MUTED)

    # Artefact brut, puis résultat normalisé
    uml(s, 820, 30, 350, "RawScanArtifact", ["plugin_name : str", "scan_type : ScanType",
                                              "tool : str", "stdout : str", "exit_code : int"], tint=Z_STO)
    s.edge([(560, 110), (820, 110)], dashed=True, label="« produit »", label_at=(690, 92))
    uml(s, 820, 290, 350, "Finding", [
        "id : str (empreinte SHA-256)", "source : ScanType", "tool : str", "title : str",
        "location : Location", "cve, cwe : List[str]", "severity_raw : Severity",
        "confidence_raw : Confidence", "exposure : Exposure", "risk_score : float (0–100)",
        "related_ids : List[str]", "llm_remediation : str"], ["fingerprint() : str"], tint=C)
    s.edge([(995, 206), (995, 290)], dashed=True, label="« normalisé en »", label_at=(1080, 250))

    # Localisation polymorphe
    h_loc = uml(s, 400, 520, 270, "Location", ["kind : str"], stereo="union", tint=C)
    # composition : losange plein côté Finding
    s.add(f'<path d="M820,575 l-14,-8 l-14,8 l14,8 z" fill="{EDGE}"/>')
    s.add(f'<path d="M792,575 H670" stroke="{EDGE}" stroke-width="1.8"/>')
    s.text(678, 565, "1", size=16, color=MUTED)
    subs = [("CodeLocation", ["file_path : str", "start_line : int", "snippet : str"]),
            ("DepsLocation", ["manifest_path : str", "package_name : str", "package_version : str"]),
            ("ContainerLocation", ["image_ref : str", "package_name : str", "package_version : str"]),
            ("NetworkLocation", ["host : str", "port : int", "service, product : str"])]
    xs = []
    for i, (n, a) in enumerate(subs):
        x = 30 + i * 290
        uml(s, x, 770, 270, n, a, tint=C, size=17)
        xs.append((x + 135, 770))
    inherit(s, 535, 520 + h_loc, xs, 725)

    s.legend(30, 975, [((X[0], X[1]), "greffons"), ((C[0], C[1]), "modèle de données"),
                       ("dashed", "dépendance")])
    s.add(f'<path d="M760,975 l-11,-10 v20 z" fill="#ffffff" stroke="{EDGE}" stroke-width="1.6"/>')
    s.add(f'<path d="M726,975 h23" stroke="{EDGE}" stroke-width="1.8"/>')
    s.text(772, 980, "généralisation", size=15, color=MUTED)
    s.add(f'<path d="M930,975 l14,-8 l14,8 l-14,8 z" fill="{EDGE}"/>')
    s.add(f'<path d="M958,975 h24" stroke="{EDGE}" stroke-width="1.8"/>')
    s.text(994, 980, "composition", size=15, color=MUTED)
    return s.render()


# ══════════════════════════════════════════════════════════════════════════
# Figure 4.4 — Diagramme de séquence d'un scan
# ══════════════════════════════════════════════════════════════════════════
def fig_4_4():
    s = Svg(1200, 900)
    parts = [(150, "Interface", "web ou ligne de commande", Z_UI),
             (450, "Cerveau", "orchestrateur Python", Z_CORE),
             (750, "Exécuteur", "conteneur éphémère", Z_EXEC),
             (1050, "Modèle de langage", "local (LM Studio)", Z_LLM)]
    top, bottom = 40, 820
    for x, name, sub, tint in parts:
        s.box(x - 130, top, 260, 70, [name, sub], tint=tint, size=20, sub_size=16)
        s.add(f'<path d="M{x},{top + 70} V{bottom}" stroke="{MUTED}" stroke-width="1.4" stroke-dasharray="6 6"/>')

    def msg(y, a, b, text, ret=False, n=None):
        x1, x2 = parts[a][0], parts[b][0]
        d = 8 if x2 > x1 else -8
        dash = ' stroke-dasharray="9 7"' if ret else ""
        s.add(f'<path d="M{x1 + d},{y} H{x2 - d}" stroke="{EDGE}" stroke-width="1.9"{dash} marker-end="url(#arr)"/>')
        tw = len(text) * 17 * 0.53
        s.add(f'<rect x="{min(x1, x2) + 38}" y="{y - 30}" width="{tw + 8}" height="26" fill="#ffffff"/>')
        s.text(min(x1, x2) + 42, y - 10, text, size=17)
        if n:
            s.add(f'<circle cx="{min(x1, x2) + 22}" cy="{y - 16}" r="12" fill="{INK}"/>')
            s.text(min(x1, x2) + 22, y - 11, str(n), size=14, color="#ffffff", bold=True, anchor="middle")

    def self_msg(y, a, text, tint, n=None):
        x = parts[a][0]
        fill, stroke = tint
        s.add(f'<rect x="{x - 8}" y="{y - 30}" width="16" height="60" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
        s.add(f'<path d="M{x + 8},{y - 18} h46 v36 h-46" fill="none" stroke="{EDGE}" stroke-width="1.8" marker-end="url(#arr)"/>')
        tw = len(text) * 17 * 0.53
        s.add(f'<rect x="{x + 60}" y="{y - 14}" width="{tw + 8}" height="26" fill="#ffffff"/>')
        s.text(x + 64, y + 6, text, size=17)
        if n:
            s.add(f'<circle cx="{x - 30}" cy="{y}" r="12" fill="{INK}"/>')
            s.text(x - 30, y + 5, str(n), size=14, color="#ffffff", bold=True, anchor="middle")

    msg(160, 0, 1, "lancer un scan (dépôt, outils)", n=1)
    self_msg(225, 1, "détecter l’environnement, planifier", Z_CORE, n=2)
    msg(310, 1, 2, "plan.json — docker run", n=3)
    self_msg(375, 2, "exécuter les scanners", Z_EXEC, n=4)
    msg(460, 2, 1, "artifacts.json (sorties brutes)", ret=True, n=5)
    self_msg(525, 1, "normaliser → corréler → noter", Z_CORE, n=6)
    msg(610, 1, 3, "résultats les plus graves, avec leur preuve", n=7)
    msg(680, 3, 1, "synthèse et remédiations", ret=True, n=8)
    msg(760, 1, 0, "rapport et tableau de bord", ret=True, n=9)

    s.legend(40, 870, [("solid", "appel"), ("dashed", "réponse ou fichier en retour"),
                       ((Z_EXEC[0], Z_EXEC[1]), "exécution isolée")])
    return s.render()


# ══════════════════════════════════════════════════════════════════════════
# Figure 3.1 — Cas d'utilisation
# ══════════════════════════════════════════════════════════════════════════
def fig_3_1():
    """Acteurs principaux à gauche, secondaires à droite : aucune ligne ne se
    croise, et les deux relations « include » relient verticalement des cas
    voisins."""
    s = Svg(1000, 930)
    s.zone(235, 40, 530, 830, "Orchestrateur de scan de vulnérabilités", Z_HOST,
           title_size=20, title_anchor="middle")
    cx, rx, ry = 500, 175, 36
    cas = {
        "UC1": (125, ["Configurer un scan"]),
        "UC3": (215, ["Suivre la progression", "en temps réel"]),
        "UC5": (305, ["Obtenir synthèse et", "remédiation (LLM)"]),
        "UC4": (400, ["Consulter les résultats", "consolidés"]),
        "UC2": (515, ["Lancer un scan"]),
        "UC6": (630, ["Exécuter un scan", "automatisé (CI)"]),
        "UC7": (730, ["Gérer le registre", "d’outils"]),
        "UC8": (820, ["Gérer comptes et", "accès aux dépôts"]),
    }
    fill, stroke = Z_CORE
    for y, lines in cas.values():
        s.add(f'<ellipse cx="{cx}" cy="{y}" rx="{rx}" ry="{ry}" fill="{fill}" '
              f'stroke="{stroke}" stroke-width="1.6"/>')
        if len(lines) == 1:
            s.text(cx, y + 6, lines[0], size=18, anchor="middle")
        else:
            s.text(cx, y - 4, lines[0], size=18, anchor="middle")
            s.text(cx, y + 18, lines[1], size=18, anchor="middle")

    def acteur(x, y, nom):
        s.add(f'<circle cx="{x}" cy="{y - 52}" r="13" fill="#ffffff" stroke="{INK}" stroke-width="2"/>')
        s.add(f'<path d="M{x},{y - 39} V{y - 6} M{x - 22},{y - 28} H{x + 22} '
              f'M{x},{y - 6} L{x - 18},{y + 20} M{x},{y - 6} L{x + 18},{y + 20}" '
              f'fill="none" stroke="{INK}" stroke-width="2"/>')
        for i, ligne in enumerate(nom):
            s.text(x, y + 46 + 22 * i, ligne, size=19, bold=True, anchor="middle")

    def bord(uc, px, py):
        """Extrémité gauche ou droite de l'ellipse : un trait qui y aboutit ne
        traverse aucune ellipse voisine."""
        return (cx - rx if px < cx else cx + rx), cas[uc][0]

    gauche = [((110, 330), ["Analyste", "sécurité"], ["UC1", "UC3", "UC5", "UC4", "UC2"]),
              ((110, 790), ["Administrateur"], ["UC7", "UC8"])]
    droite = [((890, 370), ["Développeur"], ["UC5", "UC4"]),
              ((890, 645), ["Système", "CI/CD"], ["UC6"])]
    for (x, y), nom, liens in gauche + droite:
        acteur(x, y, nom)
        ax = x + 30 if x < cx else x - 30
        for uc in liens:
            s.edge([(ax, y - 22), bord(uc, ax, y - 22)])

    # « include » : du cas qui inclut vers le cas inclus, entre ellipses voisines
    for src, dst in (("UC6", "UC2"), ("UC2", "UC4")):
        y1, y2 = cas[src][0] - ry, cas[dst][0] + ry
        s.edge([(cx, y1), (cx, y2 + 2)], dashed=True)
        s.label(cx + 70, (y1 + y2) / 2, "«include»", size=16)

    s.legend(40, 905, [("solid", "association acteur – cas d’utilisation"),
                       ("dashed", "inclusion («include»)")])
    return s.render()


if __name__ == "__main__":
    for name, fn in [("3-1_usecase", fig_3_1), ("1_architecture", fig_4_1), ("2_pipeline", fig_4_2), ("6_deploiement", fig_4_5),
                     ("4-3_classes", fig_4_3), ("4-4_sequence", fig_4_4)]:
        (OUT / f"{name}.svg").write_text(fn(), encoding="utf-8")
        print("écrit", OUT / f"{name}.svg")
