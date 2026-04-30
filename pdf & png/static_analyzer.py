"""
=============================================================
  Analyseur Statique de Fichiers — PDF & PNG
  Détection de malwares par analyse statique
=============================================================
  Dépendances :
      pip install pymupdf pillow numpy
=============================================================
"""

import os
import re
import sys
import math
import struct
import hashlib
import zlib
from pathlib import Path
from dataclasses import dataclass, field

# ── Imports optionnels ────────────────────────────────────
try:
    import fitz  # PyMuPDF
    PYMUPDF_OK = True
except ImportError:
    PYMUPDF_OK = False
    print("[WARN] PyMuPDF non installé — analyse PDF limitée. pip install pymupdf")

try:
    from PIL import Image
    import numpy as np
    PILLOW_OK = True
except ImportError:
    PILLOW_OK = False
    print("[WARN] Pillow/numpy non installé — analyse PNG limitée. pip install pillow numpy")


# ══════════════════════════════════════════════════════════
#  CONSTANTES
# ══════════════════════════════════════════════════════════

PDF_MAGIC = b"%PDF-"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

PDF_SUSPICIOUS_KEYWORDS = [
    b"/JavaScript", b"/JS",
    b"/OpenAction", b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/XFA",
    b"/URI",
    b"/SubmitForm",
    b"/ImportData",
    b"/AcroForm",
    b"eval(",
    b"unescape(",
    b"String.fromCharCode",
    b"this.exportDataObject",
    b"app.launchURL",
    b"getAnnots(",
    b"util.printf",
    b"Collab.collectEmailInfo",
]

PDF_HEX_OBFUSCATION_PATTERNS = [
    rb"/J#[0-9a-fA-F]{2}vaScript",
    rb"#[0-9a-fA-F]{2}#[0-9a-fA-F]{2}",
]

SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"wscript", b"cscript",
    b"mshta", b"regsvr32", b"rundll32",
    b"http://", b"https://", b"ftp://",
    b"\\\\", b"C:\\Users", b"C:\\Windows\\Temp",
    b"/bin/sh", b"/bin/bash",
    b"base64_decode", b"exec(", b"system(",
    b"<script", b"javascript:",
]

PNG_STANDARD_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"tRNS", b"cHRM", b"gAMA", b"iCCP",
    b"sRGB", b"bKGD", b"hIST", b"tEXt",
    b"zTXt", b"iTXt", b"pHYs", b"sBIT",
    b"sPLT", b"tIME", b"eXIf",
}

ENTROPY_HIGH_THRESHOLD = 7.5
ENTROPY_MED_THRESHOLD  = 6.5


# ══════════════════════════════════════════════════════════
#  STRUCTURES DE DONNÉES
# ══════════════════════════════════════════════════════════

@dataclass
class Indicator:
    """Un indicateur de suspicion détecté."""
    level: str        # "CRITIQUE" | "ELEVE" | "MODERE" | "INFO"
    category: str
    description: str

@dataclass
class AnalysisReport:
    """Rapport complet d'analyse d'un fichier."""
    filepath: str
    file_type: str
    file_size: int
    md5: str
    sha256: str
    entropy: float
    indicators: list         = field(default_factory=list)
    metadata: dict           = field(default_factory=dict)
    embedded_files: list     = field(default_factory=list)
    suspicious_strings: list = field(default_factory=list)
    verdict: str             = "SAIN"

    def add(self, indicator: Indicator):
        self.indicators.append(indicator)

    def finalize(self):
        """
        Verdict basé sur le niveau des indicateurs :
          - Au moins un CRITIQUE -> MALVEILLANT
          - Au moins un ELEVE    -> SUSPECT
          - Sinon                -> SAIN
        """
        levels = [ind.level for ind in self.indicators]
        if "CRITIQUE" in levels:
            self.verdict = "MALVEILLANT"
        elif "ELEVE" in levels:
            self.verdict = "SUSPECT"
        else:
            self.verdict = "SAIN"


# ══════════════════════════════════════════════════════════
#  UTILITAIRES COMMUNS
# ══════════════════════════════════════════════════════════

def compute_hashes(data: bytes) -> tuple:
    md5    = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_file_type(filepath: str) -> str:
    with open(filepath, "rb") as f:
        header = f.read(8)
    if header[:5] == PDF_MAGIC:
        return "pdf"
    if header[:8] == PNG_MAGIC:
        return "png"
    return "unknown"


def check_suspicious_strings(data: bytes, report: AnalysisReport):
    found = []
    for pattern in SUSPICIOUS_STRINGS:
        if pattern.lower() in data.lower():
            found.append(pattern.decode("utf-8", errors="replace"))
    if found:
        report.suspicious_strings = found
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Contenu",
            description = "Strings suspects : " + ", ".join(found[:8]),
        ))


def check_entropy(data: bytes, report: AnalysisReport):
    if report.entropy >= ENTROPY_HIGH_THRESHOLD:
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Entropie",
            description = f"Entropie tres elevee ({report.entropy} bits/byte) — donnees chiffrees ou compressees suspectes",
        ))
    elif report.entropy >= ENTROPY_MED_THRESHOLD:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Entropie",
            description = f"Entropie moderement elevee ({report.entropy} bits/byte)",
        ))


# ══════════════════════════════════════════════════════════
#  ANALYSE PDF
# ══════════════════════════════════════════════════════════

def analyze_pdf_keywords(data: bytes, report: AnalysisReport):
    found_keywords = []
    for kw in PDF_SUSPICIOUS_KEYWORDS:
        if kw.lower() in data.lower():
            found_keywords.append(kw.decode("utf-8", errors="replace"))

    obfuscated = []
    for pattern in PDF_HEX_OBFUSCATION_PATTERNS:
        matches = re.findall(pattern, data)
        if matches:
            obfuscated.extend([m.decode("utf-8", errors="replace") for m in matches])

    if found_keywords:
        critical_kw    = ["/JavaScript", "/JS", "/OpenAction", "/Launch", "/EmbeddedFile"]
        critical_found = [k for k in found_keywords if k in critical_kw]
        other_found    = [k for k in found_keywords if k not in critical_kw]

        if critical_found:
            report.add(Indicator(
                level       = "CRITIQUE",
                category    = "Mots-cles PDF",
                description = "Mots-cles d execution critiques : " + ", ".join(critical_found),
            ))
        if other_found:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "Mots-cles PDF",
                description = "Mots-cles suspects : " + ", ".join(other_found),
            ))

    if obfuscated:
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Obfuscation PDF",
            description = "Noms d objets encodes en hex : " + ", ".join(obfuscated[:5]),
        ))


def analyze_pdf_structure(data: bytes, report: AnalysisReport):
    # Version invalide
    version_match = re.search(rb"%PDF-(\d+\.\d+)", data)
    if version_match:
        version = version_match.group(1).decode()
        valid_versions = ["1.0","1.1","1.2","1.3","1.4","1.5","1.6","1.7","2.0"]
        if version not in valid_versions:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "Structure PDF",
                description = f"Version PDF invalide : {version}",
            ))

    # Plusieurs %%EOF
    eof_count = data.count(b"%%EOF")
    if eof_count > 1:
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Structure PDF",
            description = f"{eof_count} marqueurs %%EOF — contenu cache apres la fin officielle",
        ))

    # Trop d'ObjStm
    objstm_count = data.lower().count(b"/objstm")
    if objstm_count > 5:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Structure PDF",
            description = f"{objstm_count} streams d objets comprimes (/ObjStm)",
        ))

    # xref absente
    if b"xref" not in data and b"/XRef" not in data:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Structure PDF",
            description = "Table xref absente — structure PDF inhabituelle",
        ))

    # Chiffrement
    if b"/Encrypt" in data:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Structure PDF",
            description = "Fichier PDF chiffre (/Encrypt) — contenu masque a l analyse",
        ))


def analyze_pdf_with_pymupdf(filepath: str, report: AnalysisReport):
    if not PYMUPDF_OK:
        return

    try:
        doc = fitz.open(filepath)

        # Metadonnees
        meta = doc.metadata
        report.metadata = {k: v for k, v in meta.items() if v}

        if not meta.get("creator") and not meta.get("producer"):
            report.add(Indicator(
                level       = "MODERE",
                category    = "Metadonnees PDF",
                description = "Metadonnees creator/producer vides — falsification possible",
            ))

        # Fichiers embarques
        emb_count = doc.embfile_count()
        if emb_count > 0:
            embedded = []
            for i in range(emb_count):
                info = doc.embfile_info(i)
                embedded.append(f"{info.get('filename','?')} ({info.get('size',0)} bytes)")
            report.embedded_files = embedded
            report.add(Indicator(
                level       = "CRITIQUE",
                category    = "Fichiers embarques",
                description = f"{emb_count} fichier(s) embarque(s) : " + ", ".join(embedded),
            ))

        # URLs
        urls = []
        for page in doc:
            for link in page.get_links():
                uri = link.get("uri", "")
                if uri:
                    urls.append(uri)
        if urls:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "URLs",
                description = f"{len(urls)} URL(s) : " + ", ".join(urls[:5]),
            ))

        # PDF sans pages
        if doc.page_count == 0:
            report.add(Indicator(
                level       = "MODERE",
                category    = "Structure PDF",
                description = "PDF sans aucune page visible",
            ))

        doc.close()

    except Exception as e:
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Parseur PDF",
            description = f"Erreur de parsing PyMuPDF : {e} — structure corrompue ou intentionnellement malformee",
        ))


def analyze_pdf(filepath: str, report: AnalysisReport):
    with open(filepath, "rb") as f:
        data = f.read()

    analyze_pdf_keywords(data, report)
    analyze_pdf_structure(data, report)
    analyze_pdf_with_pymupdf(filepath, report)
    check_suspicious_strings(data, report)
    check_entropy(data, report)


# ══════════════════════════════════════════════════════════
#  ANALYSE PNG
# ══════════════════════════════════════════════════════════

def parse_png_chunks(data: bytes) -> list:
    chunks = []
    offset = 8  # skip magic bytes

    while offset < len(data):
        if offset + 8 > len(data):
            break

        length      = struct.unpack(">I", data[offset:offset+4])[0]
        chunk_type  = data[offset+4:offset+8]
        chunk_data  = data[offset+8:offset+8+length]
        crc_stored  = data[offset+8+length:offset+12+length]

        crc_computed = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
        crc_ok = (crc_stored == crc_computed)

        chunks.append({
            "type"   : chunk_type,
            "length" : length,
            "data"   : chunk_data,
            "crc_ok" : crc_ok,
            "offset" : offset,
        })

        offset += 12 + length

    return chunks


def analyze_png_structure(data: bytes, chunks: list, report: AnalysisReport):
    if not chunks:
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Structure PNG",
            description = "Aucun chunk parseable — fichier PNG corrompu ou falsifie",
        ))
        return

    chunk_types = [c["type"] for c in chunks]

    # IHDR doit etre le premier
    if chunk_types[0] != b"IHDR":
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Structure PNG",
            description = f"Premier chunk invalide : {chunk_types[0]} (attendu : IHDR)",
        ))

    # IEND doit etre le dernier
    if chunk_types[-1] != b"IEND":
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Structure PNG",
            description = f"Dernier chunk invalide : {chunk_types[-1]} (attendu : IEND)",
        ))

    # Donnees apres IEND
    iend_chunk = next((c for c in chunks if c["type"] == b"IEND"), None)
    if iend_chunk:
        after_iend = data[iend_chunk["offset"] + 12:]
        if len(after_iend) > 0:
            report.add(Indicator(
                level       = "CRITIQUE",
                category    = "Structure PNG",
                description = f"{len(after_iend)} octets caches apres le chunk IEND",
            ))

    # CRC invalides
    bad_crc = [c for c in chunks if not c["crc_ok"]]
    if bad_crc:
        names = [c["type"].decode("ascii", errors="replace") for c in bad_crc[:5]]
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Integrite PNG",
            description = f"{len(bad_crc)} chunk(s) avec CRC invalide : {names}",
        ))

    # Chunks non standard
    unknown_chunks = [c for c in chunks if c["type"] not in PNG_STANDARD_CHUNKS]
    if unknown_chunks:
        names = [c["type"].decode("ascii", errors="replace") for c in unknown_chunks]
        report.add(Indicator(
            level       = "MODERE",
            category    = "Chunks PNG",
            description = "Chunks non standard : " + str(names),
        ))

    # Contenu suspect dans les chunks texte
    text_chunks = [c for c in chunks if c["type"] in (b"tEXt", b"zTXt", b"iTXt")]
    for tc in text_chunks:
        for pattern in SUSPICIOUS_STRINGS:
            if pattern.lower() in tc["data"].lower():
                report.add(Indicator(
                    level       = "ELEVE",
                    category    = "Chunks texte PNG",
                    description = f"String suspect dans chunk {tc['type'].decode()} : {pattern.decode('utf-8','replace')}",
                ))
                break


def analyze_png_steganography(data: bytes, report: AnalysisReport):
    if not PILLOW_OK:
        return

    try:
        from io import BytesIO
        img = Image.open(BytesIO(data)).convert("RGB")
        arr = np.array(img, dtype=np.uint8)

        # Entropie des LSB
        lsb_r   = arr[:, :, 0] & 1
        lsb_g   = arr[:, :, 1] & 1
        lsb_b   = arr[:, :, 2] & 1
        lsb_all = np.concatenate([lsb_r.flatten(), lsb_g.flatten(), lsb_b.flatten()])
        lsb_bytes   = np.packbits(lsb_all).tobytes()
        lsb_entropy = compute_entropy(lsb_bytes)

        if lsb_entropy > 7.8:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "Steganographie",
                description = f"Entropie LSB tres elevee ({lsb_entropy:.3f}) — probable steganographie LSB",
            ))
        elif lsb_entropy > 7.2:
            report.add(Indicator(
                level       = "MODERE",
                category    = "Steganographie",
                description = f"Entropie LSB moderement elevee ({lsb_entropy:.3f})",
            ))

        # Image uniforme avec entropie globale elevee
        pixel_std = float(arr.std())
        if pixel_std < 15 and report.entropy > ENTROPY_MED_THRESHOLD:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "Steganographie",
                description = f"Image visuellement uniforme (std={pixel_std:.1f}) mais entropie elevee — donnees cachees probables",
            ))

    except Exception as e:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Analyse image",
            description = f"Impossible d ouvrir l image avec Pillow : {e}",
        ))


def analyze_png_metadata(data: bytes, report: AnalysisReport):
    if not PILLOW_OK:
        return

    try:
        from io import BytesIO
        img = Image.open(BytesIO(data))
        report.metadata = {k: str(v)[:200] for k, v in img.info.items()}

        w, h = img.size
        chunks = parse_png_chunks(data)
        idat_size = sum(len(c["data"]) for c in chunks if c["type"] == b"IDAT")
        if w * h > 0 and idat_size > w * h * 10:
            report.add(Indicator(
                level       = "ELEVE",
                category    = "Metadonnees PNG",
                description = f"Taille IDAT ({idat_size}) disproportionnee par rapport aux dimensions {w}x{h}",
            ))

    except Exception as e:
        report.add(Indicator(
            level       = "MODERE",
            category    = "Metadonnees PNG",
            description = f"Erreur lecture metadonnees : {e}",
        ))


def detect_polyglot(data: bytes, report: AnalysisReport):
    polyglot_signatures = {
        b"PK\x03\x04"       : "ZIP/JAR/DOCX",
        b"MZ"               : "EXE/DLL (Windows PE)",
        b"\x7fELF"          : "ELF (Linux executable)",
        b"%PDF-"            : "PDF",
        b"\xca\xfe\xba\xbe" : "Java Class",
        b"#!/"              : "Script Shell",
        b"<html"            : "HTML",
        b"<script"          : "JavaScript",
    }

    body = data[8:]  # ignore magic bytes PNG
    found = [fmt for sig, fmt in polyglot_signatures.items() if sig in body]

    if found:
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Polyglot",
            description = "Fichier polyglot — formats embarques : " + ", ".join(found),
        ))


def analyze_png(filepath: str, report: AnalysisReport):
    with open(filepath, "rb") as f:
        data = f.read()

    chunks = parse_png_chunks(data)

    analyze_png_structure(data, chunks, report)
    analyze_png_metadata(data, report)
    analyze_png_steganography(data, report)
    detect_polyglot(data, report)
    check_suspicious_strings(data, report)
    check_entropy(data, report)


# ══════════════════════════════════════════════════════════
#  MOTEUR PRINCIPAL
# ══════════════════════════════════════════════════════════

def analyze_file(filepath: str) -> AnalysisReport:
    filepath = str(Path(filepath).resolve())

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")

    with open(filepath, "rb") as f:
        data = f.read()

    file_size = len(data)
    md5, sha256 = compute_hashes(data)
    entropy = compute_entropy(data)
    file_type = detect_file_type(filepath)

    report = AnalysisReport(
        filepath  = filepath,
        file_type = file_type,
        file_size = file_size,
        md5       = md5,
        sha256    = sha256,
        entropy   = entropy,
    )

    # Magic bytes invalides
    if file_type == "unknown":
        ext = Path(filepath).suffix.lower()
        report.add(Indicator(
            level       = "CRITIQUE",
            category    = "Identification",
            description = f"Magic bytes invalides pour un fichier {ext} — extension falsifiee",
        ))
        if ext == ".pdf":
            file_type = "pdf"
        elif ext == ".png":
            file_type = "png"

    # Fichier trop petit
    if file_size < 100:
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Structure",
            description = f"Fichier anormalement petit ({file_size} octets)",
        ))

    # Dispatch par type
    if file_type == "pdf":
        analyze_pdf(filepath, report)
    elif file_type == "png":
        analyze_png(filepath, report)
    else:
        report.add(Indicator(
            level       = "ELEVE",
            category    = "Identification",
            description = "Type de fichier non reconnu — ni PDF ni PNG",
        ))

    report.finalize()
    return report


# ══════════════════════════════════════════════════════════
#  AFFICHAGE DU RAPPORT
# ══════════════════════════════════════════════════════════

COLORS = {
    "CRITIQUE"    : "\033[91m",
    "ELEVE"       : "\033[93m",
    "MODERE"      : "\033[94m",
    "INFO"        : "\033[96m",
    "SAIN"        : "\033[92m",
    "SUSPECT"     : "\033[93m",
    "MALVEILLANT" : "\033[91m",
    "RESET"       : "\033[0m",
    "BOLD"        : "\033[1m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color,'')}{text}{COLORS['RESET']}"


def print_report(report: AnalysisReport):
    sep = "=" * 60

    print(f"\n{c('BOLD', sep)}")
    print(f"{c('BOLD', '  RAPPORT D ANALYSE STATIQUE')}")
    print(f"{c('BOLD', sep)}")

    print(f"\n  {c('BOLD','Fichier')}   : {report.filepath}")
    print(f"  {c('BOLD','Type')}      : {report.file_type.upper()}")
    print(f"  {c('BOLD','Taille')}    : {report.file_size:,} octets")
    print(f"  {c('BOLD','Entropie')} : {report.entropy} bits/byte")
    print(f"  {c('BOLD','MD5')}       : {report.md5}")
    print(f"  {c('BOLD','SHA256')}    : {report.sha256}")

    if report.metadata:
        print(f"\n  {c('BOLD','-- Metadonnees --')}")
        for k, v in report.metadata.items():
            print(f"    {str(k):20s} : {str(v)[:80]}")

    if report.embedded_files:
        print(f"\n  {c('BOLD','-- Fichiers embarques --')}")
        for ef in report.embedded_files:
            print(f"    {c('CRITIQUE','[!]')}  {ef}")

    print(f"\n  {c('BOLD','-- Indicateurs detectes --')}")
    if not report.indicators:
        print(f"    {c('SAIN','[OK]')} Aucun indicateur suspect")
    else:
        for ind in report.indicators:
            icon = {
                "CRITIQUE" : "[CRITIQUE]",
                "ELEVE"    : "[ELEVE   ]",
                "MODERE"   : "[MODERE  ]",
                "INFO"     : "[INFO    ]",
            }.get(ind.level, "[?]")
            print(f"    {c(ind.level, icon)} [{ind.category}]")
            print(f"         {ind.description}")

    print(f"\n{c('BOLD', sep)}")
    print(f"  VERDICT : {c(report.verdict, c('BOLD', '  ' + report.verdict + '  '))}")
    print(f"{c('BOLD', sep)}\n")


# ══════════════════════════════════════════════════════════
#  POINT D'ENTREE CLI
# ══════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage : python static_analyzer.py <fichier.pdf|fichier.png> ...")
        sys.exit(1)

    files = sys.argv[1:]
    results = []

    for filepath in files:
        try:
            print(f"\n[*] Analyse de : {filepath}")
            report = analyze_file(filepath)
            print_report(report)
            results.append(report)
        except FileNotFoundError as e:
            print(f"[ERREUR] {e}")
        except Exception as e:
            print(f"[ERREUR] Analyse echouee pour {filepath} : {e}")

    if len(results) > 1:
        print("\n" + "=" * 60)
        print(f"  RESUME — {len(results)} fichier(s) analyse(s)")
        print("=" * 60)
        for r in results:
            name = Path(r.filepath).name
            print(f"  {c(r.verdict, f'[{r.verdict:12s}]')}  {name}")
        print()


if __name__ == "__main__":
    main()
