#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyte>=0.8.2", "textual>=0.60", "rich>=13"]
# ///
"""
exegol-shot — retrouve une commande dans les logs asciinema d'Exegol et
affiche son résultat proprement (commande épinglée en footer) pour prendre
des screenshots clean pendant un pentest.

Usage le plus simple (dans Exegol) :

    exegol-shot                 # scanne /workspace/logs et ouvre la TUI
    exegol-shot -d ./logs       # scanne un dossier précis
    exegol-shot --list          # liste les commandes trouvées (non interactif)
    exegol-shot --show 12       # affiche la commande n°12 + son résultat

TUI :
    tape pour filtrer (fuzzy) · ↑/↓ naviguer · Entrée ouvrir · Échap/q retour

Vue détail (pour le screenshot) :
    ↑/↓ ou PgUp/PgDn  défiler le résultat
    h  masquer/afficher la barre d'infos (mode clean)
    w  (dé)activer le retour à la ligne
    y  copier la commande
    q / Échap  retour à la recherche

Perf : le scan ne fait QUE repérer les commandes (lecture légère du flux, sans
émulateur de terminal), avec une barre de progression par fichier. Le rendu
complet (couleurs ANSI, barres de progression résolues, etc.) via l'émulateur
pyte n'est reconstruit que pour LA commande sélectionnée, au moment de
l'afficher — donc instantané même avec de très gros logs.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    import pyte
except ImportError:
    sys.stderr.write(
        "\n[exegol-shot] Dépendance manquante : pyte\n"
        "  Installe les dépendances :\n"
        "    pip install --break-system-packages pyte textual rich\n"
        "  (ou)  pipx run exegol_shot.py   /   uv run exegol_shot.py\n\n"
    )
    sys.exit(2)

from rich.style import Style
from rich.text import Text

__version__ = "1.3.0"

# --------------------------------------------------------------------------- #
# Détection du prompt Exegol (zsh)
#
#   [🔴][Oct 28, 2026 - 12:52:07 (CET)] exegol-dpd /workspace # la commande
#
# Le point rouge 🔴 (indicateur d'enregistrement asciinema) est imprimé par le
# prompt UNE fois par invite (zsh ne redessine ensuite que la zone de saisie,
# pas le préfixe). C'est donc une ancre fiable — un 🔴 = un prompt — pour
# découper le flux sans émuler tout le fichier. On ne rejoue dans pyte que la
# ligne de commande (au scan) ou le bloc d'une commande (à l'affichage).
#
# DEFAULT_CMD_RE extrait la commande depuis la ligne de prompt RENDUE :
#   <...> exegol-<host> <chemin> # <commande>
# --------------------------------------------------------------------------- #
REC_DOT = "🔴"
# zsh active le "bracketed paste" pendant la saisie (?2004h) et le désactive
# quand la ligne est validée (?2004l). ?2004l marque donc PRÉCISÉMENT la fin de
# la commande (avant toute sortie) — bien plus fiable qu'un '\n', car dans ce
# prompt la touche Entrée n'émet pas forcément de saut de ligne isolé.
INPUT_END = "\x1b[?2004l"
DEFAULT_CMD_RE = re.compile(
    r"^.*?\bexegol-\S+\s+.*?\s[#$»❯➜>]\s?(?P<cmd>.*)$"
)
# Titre OSC posé par zsh : juste après la validation, preexec met la commande
# dans le titre (OSC 2) — source PROPRE et complète quand le rendu de la ligne
# est brouillé (commande wrappée + repeints de coloration). On ignore le titre
# de precmd (user@host:chemin), qui n'est pas une commande.
_OSC_KIND_RE = re.compile(r"\x1b\]([0-9]+);([^\x07\x1b]*)(?:\x07|\x1b\\)")
_PRECMD_TITLE_RE = re.compile(r"^\S+@\S+:")

KNOWN_EXTS = (
    ".cast", ".asciinema", ".asciicast",
    ".cast.gz", ".asciinema.gz", ".asciicast.gz",
)

# Séquences d'échappement ANSI / contrôles, pour nettoyer une ligne sans
# passer par un émulateur complet (scan rapide).
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC ... BEL / ST
    r"|\x1b\[[0-?]*[ -/]*[@-~]"            # CSI ... (SGR, curseur, effacement…)
    r"|\x1b[()][\x20-\x7e]"                # sélection de charset
    r"|\x1b[@-Z\\-_]"                      # autres ESC simples
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# --------------------------------------------------------------------------- #
# Modèle
# --------------------------------------------------------------------------- #
@dataclass
class SLine:
    """Une ligne de terminal rendue : texte brut + segments stylés."""
    plain: str
    runs: List[Tuple[str, Optional[Style]]] = field(default_factory=list)


@dataclass
class Segment:
    """Une commande repérée dans un log.

    Au scan, seules les métadonnées légères sont remplies (commande, fichier,
    bornes dans le flux). Le rendu stylé (prompt_block / output) est produit à
    la demande via ``ensure_rendered`` — uniquement pour la commande affichée.
    """
    command: str                       # commande en texte brut (pour la recherche)
    file_label: str                    # nom du fichier source
    file_path: str
    slice_start: int                   # offset début du bloc (prompt) dans le flux
    input_end: int                     # offset fin de saisie (?2004l) = début sortie
    slice_end: int                     # offset fin du résultat dans le flux
    width: int                         # dimensions du terminal (pour le rendu)
    height: int
    out_lines_est: int = 0             # nb de lignes de sortie (estimation, pour --list)
    index: int = 0                     # numéro global (1-based), rempli après coup
    # rempli paresseusement par ensure_rendered() :
    prompt_block: Optional[List[SLine]] = None   # bloc prompt complet (footer stylé)
    output: Optional[List[SLine]] = None         # résultat de la commande (stylé)


# --------------------------------------------------------------------------- #
# Couleurs pyte -> rich
# --------------------------------------------------------------------------- #
_HEX_RE = re.compile(r"^[0-9a-fA-F]{6}$")


def _conv_color(c: Optional[str]) -> Optional[str]:
    if not c or c == "default":
        return None
    if _HEX_RE.match(c):
        return "#" + c.lower()
    if c == "brown":          # pyte appelle le jaune "brown"
        return "yellow"
    if c.startswith("bright"):
        rest = c[6:]
        if rest == "brown":
            rest = "yellow"
        return "bright_" + rest
    return c


def _style_of(ch) -> Style:
    return Style(
        color=_conv_color(ch.fg),
        bgcolor=_conv_color(ch.bg),
        bold=ch.bold or None,
        italic=ch.italics or None,
        underline=ch.underscore or None,
        strike=ch.strikethrough or None,
        reverse=ch.reverse or None,
        blink=ch.blink or None,
    )


_DEFAULT_STYLE = Style()


def _render_line(line_map, default_char) -> SLine:
    """Transforme une ligne du buffer pyte (dict col->Char) en SLine."""
    if not line_map:
        return SLine("", [])
    maxcol = max(line_map)
    runs: List[Tuple[str, Optional[Style]]] = []
    cur_chars: List[str] = []
    cur_style: Optional[Style] = None
    plain: List[str] = []
    for col in range(maxcol + 1):
        ch = line_map.get(col)
        if ch is None:
            data = " "
            style = _DEFAULT_STYLE
        else:
            data = ch.data
            if data == "":
                # 2e cellule d'un caractère large : on l'ignore
                continue
            style = _style_of(ch)
        plain.append(data)
        if style == cur_style:
            cur_chars.append(data)
        else:
            if cur_chars:
                runs.append(("".join(cur_chars), cur_style))
            cur_chars = [data]
            cur_style = style
    if cur_chars:
        runs.append(("".join(cur_chars), cur_style))

    # on enlève les espaces de fin "par défaut" (pas de fond coloré)
    while runs:
        txt, st = runs[-1]
        if (st is None or (st.bgcolor is None and not st.reverse)) and txt.strip() == "":
            runs.pop()
        else:
            stripped = txt.rstrip() if (st is None or (st.bgcolor is None and not st.reverse)) else txt
            if stripped != txt:
                runs[-1] = (stripped, st)
            break
    return SLine("".join(plain).rstrip(), runs)


# --------------------------------------------------------------------------- #
# Lecture des fichiers asciicast (v1 et v2, gzip transparent)
# --------------------------------------------------------------------------- #
def _read_text(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(2)
        fh.seek(0)
        raw = fh.read()
    if head == b"\x1f\x8b" or path.lower().endswith(".gz"):
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", "replace")


def load_asciicast(path: str):
    """Retourne (width, height, data_str). data_str = flux de sortie concaténé."""
    text = _read_text(path).lstrip("﻿")
    first, _, rest = text.partition("\n")
    hdr = None
    try:
        hdr = json.loads(first)
    except Exception:
        hdr = None

    # asciicast v2 : 1re ligne = header JSON, puis une ligne JSON par event
    if isinstance(hdr, dict) and "version" in hdr and "stdout" not in hdr:
        out: List[str] = []
        for line in rest.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if isinstance(ev, list) and len(ev) >= 3 and ev[1] == "o":
                out.append(ev[2])
        return hdr.get("width"), hdr.get("height"), "".join(out)

    # asciicast v1 : objet JSON unique avec "stdout"
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "stdout" in obj:
            out = [d for (_t, d) in obj["stdout"]]
            return obj.get("width"), obj.get("height"), "".join(out)
    except Exception:
        pass

    # sinon : flux brut
    return None, None, text


def render_stream(data: str, width, height) -> List[SLine]:
    """Rejoue un flux (string) dans un émulateur pyte et renvoie les lignes rendues.

    Utilisé UNIQUEMENT pour la portion de flux d'une commande sélectionnée, pas
    pour l'ensemble du fichier — c'est ce qui rend l'affichage instantané.
    """
    screen = pyte.HistoryScreen(int(width or 80), int(height or 24),
                                history=200000, ratio=0.5)
    stream = pyte.Stream(screen)
    stream.feed(data)
    default_char = screen.default_char

    lines: List[SLine] = []
    for line_map in screen.history.top:          # lignes sorties par le haut
        lines.append(_render_line(line_map, default_char))
    for row in range(screen.lines):              # écran visible
        lines.append(_render_line(screen.buffer.get(row, {}), default_char))

    # on retire les lignes vides de fin
    while lines and lines[-1].plain == "":
        lines.pop()
    return lines


# --------------------------------------------------------------------------- #
# Découpage en segments (commande -> résultat)
# --------------------------------------------------------------------------- #
def _cmd_from_chunk(chunk: str, w: int, h: int, cmd_re: re.Pattern) -> Optional[str]:
    """Émule la zone de saisie et renvoie la commande TAPÉE si elle tient sur
    une seule ligne de terminal (cas propre et majoritaire). Si la commande a
    wrappé (ligne pleine), le rendu zle (repeints de coloration avec sauts de
    curseur) n'est pas fiable : on renvoie None pour que l'appelant se rabatte
    sur le titre OSC (``_preexec_cmd``). pyte.Screen simple = scan rapide."""
    screen = pyte.Screen(w, h)
    pyte.Stream(screen).feed(chunk)
    rows = screen.display                     # lignes complètes, padding espaces
    pi = None
    for i, line in enumerate(rows):
        m = cmd_re.match(line.rstrip())
        if m and (m.group("cmd") or "").strip():
            pi = i
            break
    if pi is None:
        return None
    if w >= 1 and rows[pi][-1] != " ":        # ligne pleine -> commande wrappée
        return None                           # -> rendu non fiable, on utilisera l'OSC
    m = cmd_re.match(rows[pi].rstrip())
    return m.group("cmd").rstrip() if m else None


def _oneline(s: str) -> str:
    """Aplati une commande sur une seule ligne (une commande multi-lignes garde
    ses \\n dans le titre OSC) : indispensable pour l'affichage en liste."""
    return re.sub(r"[\r\n\t\x00-\x08\x0b-\x1f]+", " ", s).strip()


def _preexec_cmd(region: str) -> Optional[str]:
    """Commande propre que zsh (preexec) pose dans le titre du terminal juste
    après la validation. On prend le 1er titre OSC 2 qui n'est pas un titre de
    precmd (user@host:chemin)."""
    for m in _OSC_KIND_RE.finditer(region):
        kind, val = m.group(1), m.group(2).strip()
        if not val or _PRECMD_TITLE_RE.match(val):
            continue
        if kind == "2":
            return val
    return None


def _rebuild_prompt_line(sl: SLine, command: str, cmd_re: re.Pattern) -> SLine:
    """Footer propre : garde le préfixe stylé du prompt (jusqu'au sigil, toujours
    propre même si la commande est brouillée) et y accole la commande propre."""
    m = cmd_re.match(sl.plain)
    if not m:
        return sl
    cut = m.start("cmd")
    runs: List[Tuple[str, Optional[Style]]] = []
    pos = 0
    for txt, st in sl.runs:
        if pos >= cut:
            break
        end = pos + len(txt)
        runs.append((txt if end <= cut else txt[:cut - pos], st))
        pos = end
    if not runs and sl.plain[:cut]:
        runs = [(sl.plain[:cut], None)]
    # garantit un espace entre le prompt et la commande (le rendu brouillé d'une
    # commande wrappée peut l'avoir mangé)
    if runs and not runs[-1][0].endswith(" ") and not command.startswith(" "):
        runs.append((" ", None))
    runs.append((command, Style(bold=True, color="#ffffff")))
    return SLine("".join(t for t, _ in runs), runs)


def _clean_line(raw: str) -> str:
    """Nettoie une ligne physique du flux (strip ANSI, \\r, contrôles) sans
    émulateur. Utilisé seulement par le repli sans ancre (logs non interactifs)."""
    if not raw:
        return ""
    if "\x1b" in raw:
        raw = _ANSI_RE.sub("", raw)
    if "\r" in raw:
        # le \r final appartient au saut de ligne \r\n (coupé par split('\n'))
        raw = raw.rstrip("\r")
        # approximation d'un retour chariot : on garde ce qui suit le dernier \r
        if "\r" in raw:
            raw = raw.rsplit("\r", 1)[-1]
    if _CTRL_RE.search(raw):
        raw = _CTRL_RE.sub("", raw)
    return raw.rstrip()


def _prompt_line_start(data: str, before: int) -> int:
    """Début de la ligne du dernier prompt (🔴) situé avant ``before``.

    Le prompt Exegol a une HORLOGE : il se redessine chaque seconde et émet un
    🔴 à chaque tick. On ne peut donc PAS compter 1 🔴 = 1 prompt. On repère le
    dernier 🔴 (le tick final, = état committé du prompt) avant la validation."""
    p = data.rfind(REC_DOT, 0, before)
    if p == -1:
        return 0
    return data.rfind("\n", 0, p) + 1


def scan_file(path: str, cmd_re: re.Pattern, on_progress=None) -> List[Segment]:
    """Scan d'un fichier. Ancre = ?2004l (zsh désactive le bracketed paste à la
    validation) : un ?2004l = UNE commande réellement exécutée. Bien plus fiable
    que 🔴 (émis à chaque tick d'horloge du prompt). Pour chaque commande, on
    mémorise les bornes (prompt / fin de saisie / fin de sortie) ; la sortie
    complète n'est rendue qu'à l'affichage. ``on_progress(pct)`` : progression."""
    width, height, data = load_asciicast(path)
    w = int(width or 80)
    h = int(height or 24)
    label = os.path.basename(path)

    # positions des validations (une par commande exécutée)
    ends: List[int] = []
    pos = data.find(INPUT_END)
    while pos != -1:
        ends.append(pos)
        pos = data.find(INPUT_END, pos + 1)

    if not ends:
        # repli : pas de bracketed paste (log non interactif ?). Scan ligne à ligne.
        if on_progress is not None:
            on_progress(100)
        return _scan_lines_fallback(data, w, h, cmd_re, label, path)

    segs: List[Segment] = []
    n = len(ends)
    last_pct = -1
    for i, e in enumerate(ends):
        if on_progress is not None:
            pct = int(i * 100 / n)
            if pct != last_pct:
                on_progress(pct)
                last_pct = pct
        ls = _prompt_line_start(data, e)             # début ligne du prompt committé
        # fin de la sortie = début du prompt de la commande SUIVANTE (ou, pour la
        # dernière, le dernier prompt restant à l'écran, sinon la fin du flux).
        if i + 1 < n:
            out_end = _prompt_line_start(data, ends[i + 1])
        else:
            last_dot = data.rfind(REC_DOT)
            lp = data.rfind("\n", 0, last_dot) + 1 if last_dot != -1 else len(data)
            out_end = lp if lp > e else len(data)
        if out_end <= e:
            out_end = len(data)

        # commande : rendu de la ligne tapée si elle ne wrappe pas (propre,
        # forme réellement tapée) ; sinon titre OSC du preexec (propre, complet).
        command = _cmd_from_chunk(data[ls:e], w, h, cmd_re)
        if not command:
            command = _preexec_cmd(data[e:min(out_end, e + 4096)])
        if not command:
            continue
        command = _oneline(command)
        if not command:
            continue
        out_est = data.count("\n", e, out_end)
        segs.append(Segment(
            command=command,
            file_label=label,
            file_path=path,
            slice_start=ls,
            input_end=e,
            slice_end=out_end,
            width=w,
            height=h,
            out_lines_est=out_est,
        ))
    if on_progress is not None:
        on_progress(100)
    return segs


def _scan_lines_fallback(data, w, h, cmd_re, label, path) -> List[Segment]:
    """Repli sans ancre : découpe par lignes nettoyées (logs non interactifs)."""
    parts = data.split("\n")
    lines: List[Tuple[int, int, str]] = []
    offset = 0
    for raw in parts:
        start = offset
        offset += len(raw) + 1
        lines.append((start, offset, _clean_line(raw)))
    segs: List[Segment] = []
    n = len(lines)
    i = 0
    while i < n:
        m = cmd_re.match(lines[i][2])
        if m and (m.group("cmd") or "").strip():
            command = m.group("cmd").rstrip()
            j = i + 1
            while j < n:
                mj = cmd_re.match(lines[j][2])
                if mj and (mj.group("cmd") or "").strip():
                    break
                j += 1
            out_est = sum(1 for kk in range(i + 1, j) if lines[kk][2].strip())
            segs.append(Segment(
                command=command, file_label=label, file_path=path,
                slice_start=lines[i][0],
                input_end=lines[i][1],            # après la ligne de commande
                slice_end=lines[j - 1][1] if j - 1 < n else offset,
                width=w, height=h, out_lines_est=out_est,
            ))
            i = j
        else:
            i += 1
    return segs


def ensure_rendered(seg: Segment, cmd_re: re.Pattern) -> None:
    """Rend (paresseusement) le prompt stylé + la sortie d'UNE commande, en ne
    rejouant dans pyte que la portion du flux correspondante. Résultat caché
    sur le segment : les ré-ouvertures sont instantanées.

    La SORTIE est rendue à partir de la fin de saisie (input_end) : elle ne
    contient donc jamais la ligne de commande (ni ses repeints de coloration
    quand elle wrappe). Le PROMPT du footer est reconstruit : préfixe stylé +
    la commande propre (seg.command)."""
    if seg.output is not None:
        return
    try:
        _w, _h, data = load_asciicast(seg.file_path)
        out_lines = render_stream(data[seg.input_end:seg.slice_end],
                                  seg.width, seg.height)
        in_lines = render_stream(data[seg.slice_start:seg.input_end],
                                 seg.width, seg.height)
    except Exception:
        seg.prompt_block = [SLine(seg.command, [(seg.command, Style(bold=True))])]
        seg.output = []
        return
    # la sortie commence après ?2004l\r\r\n : on enlève les lignes vides de tête
    while out_lines and out_lines[0].plain == "":
        out_lines.pop(0)
    seg.output = out_lines
    # footer : préfixe du prompt (rendu, propre) + commande propre
    prompt_sl = next((sl for sl in in_lines if cmd_re.match(sl.plain)), None)
    seg.prompt_block = [
        _rebuild_prompt_line(prompt_sl, seg.command, cmd_re) if prompt_sl
        else SLine(seg.command, [(seg.command, Style(bold=True, color="#ffffff"))])
    ]


# --------------------------------------------------------------------------- #
# Découverte des fichiers / dossiers
# --------------------------------------------------------------------------- #
def discover_dirs(explicit: Optional[List[str]]) -> List[str]:
    if explicit:
        return [os.path.abspath(os.path.expanduser(d)) for d in explicit]
    import glob
    candidates: List[str] = []
    if os.path.isdir("/workspace/logs"):
        candidates.append("/workspace/logs")
    home = os.path.expanduser("~")
    candidates += sorted(
        d for d in glob.glob(os.path.join(home, ".exegol", "workspaces", "*", "logs"))
        if os.path.isdir(d)
    )
    if os.path.isdir("logs"):
        candidates.append(os.path.abspath("logs"))
    if os.path.isdir(os.path.join(home, ".exegol")):
        # fallback large : tout logs/ sous ~/.exegol
        candidates += sorted(
            d for d in glob.glob(os.path.join(home, ".exegol", "**", "logs"),
                                 recursive=True)
            if os.path.isdir(d)
        )
    seen, out = set(), []
    for d in candidates:
        rp = os.path.realpath(d)
        if rp not in seen:
            seen.add(rp)
            out.append(d)
    return out


def find_files(dirs: List[str], force_all: bool) -> List[str]:
    files: List[str] = []
    for d in dirs:
        if not os.path.isdir(d):
            if os.path.isfile(d):
                files.append(d)
            continue
        matched = []
        for root, _sub, names in os.walk(d):
            for name in names:
                p = os.path.join(root, name)
                if name.lower().endswith(KNOWN_EXTS):
                    matched.append(p)
        if not matched and force_all:
            # dossier donné explicitement sans extension connue -> on tente tout
            for root, _sub, names in os.walk(d):
                for name in names:
                    matched.append(os.path.join(root, name))
        files += matched
    # dédup + tri par date de modif (plus récent d'abord)
    uniq = sorted(set(files), key=lambda p: os.path.getmtime(p), reverse=True)
    return uniq


# --------------------------------------------------------------------------- #
# Barre de progression (scan)
# --------------------------------------------------------------------------- #
def _make_progress(total_files: int):
    """Retourne (start, update, done). N'affiche rien si stderr n'est pas un TTY
    (pour ne pas polluer une sortie redirigée)."""
    enabled = sys.stderr.isatty()
    state = {"n": 0, "name": "", "pct": 0}

    def draw() -> None:
        if not enabled:
            return
        barlen = 20
        filled = int(barlen * state["pct"] / 100)
        bar = "█" * filled + "░" * (barlen - filled)
        sys.stderr.write(
            f"\r[exegol-shot] {state['n']:>2}/{total_files}  "
            f"{state['name']:<26.26} [{bar}] {state['pct']:3d}%"
        )
        sys.stderr.flush()

    def start(n: int, name: str) -> None:
        state.update(n=n, name=name, pct=0)
        draw()

    def update(pct: int) -> None:
        if pct != state["pct"]:
            state["pct"] = pct
            draw()

    def done() -> None:
        if enabled:
            sys.stderr.write("\r" + " " * 72 + "\r")
            sys.stderr.flush()

    return start, update, done


def build_segments(files: List[str], cmd_re: re.Pattern,
                   verbose: bool = True) -> List[Segment]:
    all_segs: List[Segment] = []
    total = len(files)
    start = update = done = None
    if verbose:
        start, update, done = _make_progress(total)
    for n, path in enumerate(files, 1):
        if start:
            start(n, os.path.basename(path))
        try:
            segs = scan_file(path, cmd_re, on_progress=update)
        except Exception:
            continue
        all_segs.extend(segs)
    if done:
        done()
    for k, s in enumerate(all_segs, 1):
        s.index = k
    return all_segs


# --------------------------------------------------------------------------- #
# Fuzzy matching maison (sans dépendance)
# --------------------------------------------------------------------------- #
def fuzzy(query: str, text: str):
    """Retourne (score, positions) ou None. Insensible à la casse."""
    if not query:
        return (0.0, [])
    ql = query.lower()
    tl = text.lower()
    positions: List[int] = []
    ti = 0
    score = 0.0
    prev = -2
    for qc in ql:
        idx = tl.find(qc, ti)
        if idx == -1:
            return None
        positions.append(idx)
        score += 3.0 if idx == prev + 1 else 1.0
        if idx == 0 or not tl[idx - 1].isalnum():
            score += 2.0
        prev = idx
        ti = idx + 1
    score -= 0.001 * positions[0]
    score -= 0.0004 * len(text)
    return (score, positions)


def filter_segments(segments: List[Segment], query: str):
    q = query.strip()
    if not q:
        return [(s, []) for s in segments]
    scored = []
    for s in segments:
        r = fuzzy(q, s.command)
        if r is not None:
            scored.append((r[0], s, r[1]))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [(s, pos) for _sc, s, pos in scored]


# --------------------------------------------------------------------------- #
# Conversion runs -> rich Text
# --------------------------------------------------------------------------- #
def lines_to_text(slines: List[SLine]) -> Text:
    t = Text(no_wrap=False)
    last = len(slines) - 1
    for i, sl in enumerate(slines):
        if not sl.runs and sl.plain:
            t.append(sl.plain)
        for txt, st in sl.runs:
            t.append(txt, style=st)
        if i != last:
            t.append("\n")
    return t


# --------------------------------------------------------------------------- #
# Modes non interactifs
# --------------------------------------------------------------------------- #
def cmd_list(segments: List[Segment], color: str) -> int:
    from rich.console import Console
    con = Console(force_terminal=(color == "always"),
                  no_color=(color == "never"))
    if not segments:
        con.print("[yellow]Aucune commande trouvée.[/]")
        return 1
    for s in segments:
        con.print(
            f"[grey42]{s.index:>4}[/]  "
            f"[grey42]{s.file_label:<24.24}[/]  "
            f"[white]{s.command}[/]  "
            f"[grey30]({s.out_lines_est} l.)[/]",
            soft_wrap=True,      # 1 ligne par commande même redirigé (pas de wrap dur)
        )
    return 0


def cmd_show(segments: List[Segment], index: int, color: str,
             cmd_re: re.Pattern) -> int:
    from rich.console import Console
    con = Console(force_terminal=(color == "always"),
                  no_color=(color == "never"))
    seg = next((s for s in segments if s.index == index), None)
    if seg is None:
        con.print(f"[red]Index {index} introuvable[/] (1..{len(segments)}).")
        return 1
    ensure_rendered(seg, cmd_re)
    # prompt + commande, puis résultat (ordre shell naturel)
    con.print(lines_to_text(seg.prompt_block))
    if seg.output:
        con.print(lines_to_text(seg.output))
    return 0


# --------------------------------------------------------------------------- #
# TUI (Textual)
# --------------------------------------------------------------------------- #
def make_app(segments: List[Segment], source_label: str, cmd_re: re.Pattern):
    from textual.app import App, ComposeResult
    from textual.screen import Screen
    from textual.widgets import Input, Static, OptionList
    from textual.widgets.option_list import Option
    from textual.containers import VerticalScroll
    from textual import events

    MAX_ROWS = 200

    def row_text(seg: Segment, positions: List[int]) -> Text:
        line = Text(overflow="ellipsis", no_wrap=True)
        line.append(f"{seg.index:>4} ", style="grey35")
        line.append(f"{seg.file_label:<20.20} ", style="grey42")
        cmd = Text(seg.command, style="white")
        for p in positions:
            if 0 <= p < len(seg.command):
                cmd.stylize("bold #ffd75f", p, p + 1)
        line.append_text(cmd)
        return line

    class DetailScreen(Screen):
        BINDINGS = [
            ("escape", "back", "Retour"),
            ("q", "back", "Retour"),
            ("h", "toggle_bar", "Infos"),
            ("w", "toggle_wrap", "Wrap"),
            ("y", "copy_cmd", "Copier"),
        ]
        CSS = """
        DetailScreen { background: #0b0e14; }
        #topbar {
            dock: top; height: 1; padding: 0 1;
            background: #141925; color: #8b96a8;
        }
        #outscroll {
            background: #0b0e14; padding: 1 2 0 2; scrollbar-size: 1 1;
        }
        #out { width: 100%; }
        #cmdfooter {
            dock: bottom; padding: 1 2; height: auto; max-height: 10;
            background: #0d1117; color: #e6e6e6;
            border-top: solid #2b3345;
        }
        """

        def __init__(self, seg: Segment, total: int):
            super().__init__()
            self.seg = seg
            self.total = total
            self.show_bar = True
            self.wrap = False
            self.ready = seg.output is not None   # déjà rendu (cache) ?

        def compose(self) -> ComposeResult:
            yield Static(self._bar_text(), id="topbar")
            with VerticalScroll(id="outscroll"):
                yield Static(self._out_text(), id="out")
            # footer : commande brute tout de suite, prompt stylé après rendu
            footer = lines_to_text(self.seg.prompt_block) if self.ready \
                else Text(self.seg.command, style="bold #e6e6e6")
            yield Static(footer, id="cmdfooter")

        def on_mount(self) -> None:
            self.query_one("#outscroll").focus()
            if not self.ready:
                # on laisse peindre « ⏳ Chargement… » (1 frame), puis on rend la
                # sortie. pyte étant du Python pur (CPU, GIL), le rendre dans un
                # thread ne libérerait pas vraiment la TUI : on le fait donc en
                # synchrone, mais seulement après avoir affiché le loader — et
                # uniquement pour la commande ouverte (pas de plafonnement).
                self.set_timer(0.05, self._render_now)

        def _render_now(self) -> None:
            ensure_rendered(self.seg, self.app._cmd_re)
            self.ready = True
            self.query_one("#out", Static).update(self._out_text())
            self.query_one("#cmdfooter", Static).update(
                lines_to_text(self.seg.prompt_block))

        def _out_text(self) -> Text:
            if not self.ready:
                return Text("⏳  Chargement de la sortie…", style="grey42 italic")
            if not self.seg.output:
                return Text("(pas de sortie capturée)", style="grey42 italic")
            out = lines_to_text(self.seg.output)
            out.no_wrap = not self.wrap
            return out

        def _bar_text(self) -> str:
            return (f" {self.seg.file_label}  ·  commande {self.seg.index}/{self.total}"
                    f"   [↑↓/PgUp/PgDn] défiler  ·  h infos  ·  w wrap  ·  y copier  ·  q retour")

        def action_back(self) -> None:
            self.app.pop_screen()

        def action_toggle_bar(self) -> None:
            self.show_bar = not self.show_bar
            self.query_one("#topbar").display = self.show_bar

        def action_toggle_wrap(self) -> None:
            self.wrap = not self.wrap
            self.query_one("#out", Static).update(self._out_text())

        def action_copy_cmd(self) -> None:
            try:
                self.app.copy_to_clipboard(self.seg.command)
                self.notify("Commande copiée", timeout=2)
            except Exception:
                self.notify("Copie non supportée par ce terminal", severity="warning",
                            timeout=2)

        def on_key(self, event: events.Key) -> None:
            sc = self.query_one("#outscroll")
            k = event.key
            if k in ("down", "j"):
                sc.scroll_down(); event.stop()
            elif k in ("up", "k"):
                sc.scroll_up(); event.stop()
            elif k in ("pagedown", "space", "f"):
                sc.scroll_page_down(); event.stop()
            elif k in ("pageup", "b"):
                sc.scroll_page_up(); event.stop()
            elif k in ("home", "g"):
                sc.scroll_home(); event.stop()
            elif k in ("end", "G"):
                sc.scroll_end(); event.stop()

    class SearchScreen(Screen):
        CSS = """
        SearchScreen { background: #0b0e14; }
        #header {
            height: 3; padding: 1 2 0 2; background: #141925;
            color: #c9d4e4;
        }
        #search {
            height: 1; margin: 1 2 1 2; padding: 0 1;
            background: #1b2130; color: #e6e6e6; border: none;
        }
        #search:focus { background: #243150; border: none; }
        #results {
            background: #0b0e14; scrollbar-size: 1 1; height: 1fr;
            padding: 0 1; border: none;
        }
        #results > .option-list--option { padding: 0 1; }
        #results > .option-list--option-highlighted { background: #1b2a44; }
        #results:focus > .option-list--option-highlighted { background: #24385e; }
        #hint { dock: bottom; height: 1; padding: 0 2; background: #141925;
                color: #6b7686; }
        """

        def __init__(self, segments, source_label):
            super().__init__()
            self.segments = segments
            self.source_label = source_label
            self.filtered = [(s, []) for s in segments]
            self._debounce = None

        def compose(self) -> ComposeResult:
            yield Static(self._header(), id="header")
            yield Input(placeholder="🔎  Rechercher une commande…", id="search")
            # OptionList : rend des lignes (pas un widget par ligne comme ListView)
            # -> reconstruction du listing bien plus légère = TUI fluide.
            yield OptionList(id="results")
            yield Static(" ↑/↓ naviguer   ·   Entrée afficher   ·   Échap quitter",
                         id="hint")

        def _header(self) -> Text:
            t = Text()
            t.append("exegol-shot", style="bold #4b9fff")
            t.append("  ·  screenshots de commandes depuis les logs asciinema\n",
                     style="grey50")
            t.append(f"{len(self.segments)} commandes", style="#c9d4e4")
            t.append(f"   ·   {self.source_label}", style="grey42")
            return t

        def on_mount(self) -> None:
            self._refresh("")
            self.query_one("#search", Input).focus()

        def _refresh(self, query: str) -> None:
            self.filtered = filter_segments(self.segments, query)
            ol = self.query_one("#results", OptionList)
            ol.clear_options()
            opts = [Option(row_text(s, pos))
                    for s, pos in self.filtered[:MAX_ROWS]]
            if opts:
                ol.add_options(opts)
                ol.highlighted = 0
            self._update_hint()

        def _update_hint(self) -> None:
            shown = min(len(self.filtered), MAX_ROWS)
            extra = "" if len(self.filtered) <= MAX_ROWS \
                else f" (sur {len(self.filtered)})"
            self.query_one("#hint", Static).update(
                f" {shown} résultat(s){extra}   ·   ↑/↓ naviguer   ·   "
                f"Entrée afficher   ·   Échap quitter"
            )

        def on_input_changed(self, event: Input.Changed) -> None:
            # debounce : on ne refiltre/reconstruit qu'après une courte pause de
            # frappe, pour ne pas rejouer le listing à chaque touche.
            if self._debounce is not None:
                self._debounce.stop()
            q = event.value
            self._debounce = self.set_timer(0.08, lambda: self._refresh(q))

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self._open_current()

        def on_option_list_option_selected(self, event) -> None:
            self._open_current()

        def _open_current(self) -> None:
            ol = self.query_one("#results", OptionList)
            idx = ol.highlighted
            if idx is None or idx >= len(self.filtered):
                return
            seg = self.filtered[idx][0]
            self.app.push_screen(DetailScreen(seg, len(self.segments)))

        def on_key(self, event: events.Key) -> None:
            ol = self.query_one("#results", OptionList)
            n = min(len(self.filtered), MAX_ROWS)
            if n == 0:
                return
            cur = ol.highlighted or 0
            if event.key == "down":
                ol.highlighted = min(n - 1, cur + 1); event.stop()
            elif event.key == "up":
                ol.highlighted = max(0, cur - 1); event.stop()
            elif event.key == "pagedown":
                ol.highlighted = min(n - 1, cur + 10); event.stop()
            elif event.key == "pageup":
                ol.highlighted = max(0, cur - 10); event.stop()

    class ExegolShotApp(App):
        TITLE = "exegol-shot"
        BINDINGS = [("ctrl+c", "quit", "Quitter")]

        def __init__(self, segments, source_label, cmd_re):
            super().__init__()
            self._segments = segments
            self._source_label = source_label
            self._cmd_re = cmd_re

        def on_mount(self) -> None:
            self.push_screen(SearchScreen(self._segments, self._source_label))

    return ExegolShotApp(segments, source_label, cmd_re)


def run_tui(segments: List[Segment], source_label: str, cmd_re: re.Pattern) -> int:
    make_app(segments, source_label, cmd_re).run()
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="exegol-shot",
        description="Retrouve une commande dans les logs asciinema d'Exegol et "
                    "affiche son résultat proprement pour des screenshots de pentest.",
    )
    ap.add_argument("-d", "--dir", action="append", metavar="DOSSIER",
                    help="Dossier de logs à scanner (répétable). "
                         "Défaut : /workspace/logs puis ~/.exegol/workspaces/*/logs")
    ap.add_argument("--list", action="store_true",
                    help="Liste les commandes trouvées et quitte.")
    ap.add_argument("--show", type=int, metavar="N",
                    help="Affiche la commande n°N (prompt + résultat) et quitte.")
    ap.add_argument("--prompt-regex", metavar="RE",
                    help="Regex perso appliquée à la ligne de prompt RENDUE "
                         "(groupe 'cmd'). Par défaut : prompt zsh Exegol.")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                    help="Couleurs pour --list/--show (défaut: auto).")
    ap.add_argument("-V", "--version", action="version",
                    version=f"exegol-shot {__version__}")
    args = ap.parse_args(argv)

    cmd_re = DEFAULT_CMD_RE
    if args.prompt_regex:
        try:
            cmd_re = re.compile(args.prompt_regex)
            if "cmd" not in cmd_re.groupindex:
                sys.stderr.write("[exegol-shot] La regex doit contenir un groupe "
                                 "nommé (?P<cmd>...).\n")
                return 2
        except re.error as e:
            sys.stderr.write(f"[exegol-shot] Regex invalide : {e}\n")
            return 2

    dirs = discover_dirs(args.dir)
    if not dirs:
        sys.stderr.write(
            "[exegol-shot] Aucun dossier de logs trouvé.\n"
            "  Lance le shell Exegol avec le logging activé (exegol start ... -l),\n"
            "  ou précise le dossier :  exegol-shot -d /chemin/vers/logs\n"
        )
        return 1

    files = find_files(dirs, force_all=bool(args.dir))
    if not files:
        sys.stderr.write(
            "[exegol-shot] Aucun fichier asciinema (.cast/.asciinema) dans :\n"
            + "".join(f"    - {d}\n" for d in dirs)
            + "  Précise un autre dossier avec -d.\n"
        )
        return 1

    segments = build_segments(files, cmd_re)

    if not segments:
        sys.stderr.write(
            f"[exegol-shot] {len(files)} fichier(s) lus mais aucune commande détectée.\n"
            "  Le prompt n'est peut-être pas le prompt Exegol standard : essaie "
            "--prompt-regex '^...(?P<cmd>.*)$'.\n"
        )
        return 1

    if args.list:
        return cmd_list(segments, args.color)
    if args.show is not None:
        return cmd_show(segments, args.show, args.color, cmd_re)

    label = dirs[0] if len(dirs) == 1 else f"{len(dirs)} dossiers · {len(files)} fichiers"
    return run_tui(segments, label, cmd_re)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
