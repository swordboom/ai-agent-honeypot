"""
Multi-language Indian scam detection (Feature 11).

Indian scammers rarely write clean English. They write native script
("आपका खाता बंद हो जाएगा"), romanized vernacular ("aapka account band ho jayega"),
or code-mixed ("your KYC pending hai, turant update karo"). All three carry the
same threat, so all three have to score.

Two independent signals are produced:
  1. `detect_language` - which language the scammer is operating in.
  2. `scan` - weighted scam terms matched across every supported lexicon,
     so a code-mixed message scores on its Hindi half and its English half.

ponytail: lexicon + script ranges, no fastText/langdetect dependency. Swap in a
model only if recall on real traffic proves insufficient - the lexicon is the
part that carries the domain knowledge either way.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Unicode block ranges that identify a script unambiguously.
_SCRIPT_RANGES: Tuple[Tuple[int, int, str], ...] = (
    (0x0900, 0x097F, "devanagari"),  # Hindi + Marathi
    (0x0980, 0x09FF, "bengali"),
    (0x0B80, 0x0BFF, "tamil"),
    (0x0C00, 0x0C7F, "telugu"),
    (0x0A80, 0x0AFF, "gujarati"),
    (0x0C80, 0x0CFF, "kannada"),
    (0x0D00, 0x0D7F, "malayalam"),
    (0x0A00, 0x0A7F, "gurmukhi"),  # Punjabi
    (0x0600, 0x06FF, "arabic"),  # Urdu
)

_SCRIPT_TO_LANG: Dict[str, str] = {
    "bengali": "bn",
    "tamil": "ta",
    "telugu": "te",
    "gujarati": "gu",
    "kannada": "kn",
    "malayalam": "ml",
    "gurmukhi": "pa",
    "arabic": "ur",
}

LANGUAGE_NAMES: Dict[str, str] = {
    "en": "English",
    "hi": "Hindi",
    "bn": "Bengali",
    "ta": "Tamil",
    "te": "Telugu",
    "mr": "Marathi",
    "gu": "Gujarati",
    "kn": "Kannada",
    "ml": "Malayalam",
    "pa": "Punjabi",
    "ur": "Urdu",
    "unknown": "Unknown",
}

# Devanagari is shared by Hindi and Marathi; these words appear in one and not the other.
_MARATHI_MARKERS = ("आहे", "करा", "तुमच्या", "तुमचे", "खाते", "पाठवा", "ताबडतोब", "बक्षीस", "नाहीतर", "कृपया करून")
_HINDI_MARKERS = ("है", "करें", "आपका", "आपके", "खाता", "भेजें", "भेजो", "तुरंत", "जाएगा", "कीजिए")

# Romanized (Latin-script) markers, used when there is no native script at all.
_ROMAN_MARKERS: Dict[str, Tuple[str, ...]] = {
    "hi": (
        "aapka", "aapke", "aapki", "apka", "karo", "karein", "kijiye", "jayega", "jaayega",
        "turant", "jaldi", "kripya", "bhejo", "bhejein", "paise", "rupaye", "khata",
        "band ho", "bandh ho", "nahi to", "hoga", "chahiye", "abhi", "sahi", "warna",
    ),
    "bn": (
        "apnar", "apni", "korun", "koren", "pathan", "pathao", "taka", "bondho",
        "ekhoni", "taratari", "hobe", "dorkar", "noile", "jachai",
    ),
    "ta": (
        "ungal", "unga", "panam", "anuppu", "anupungal", "kanakku", "udanadiyaga",
        "seiyavum", "seyyungal", "illainaal", "irukku", "vangi",
    ),
    "te": (
        "mee ", "meeru", "dabbu", "pampandi", "ventane", "khatha", "cheyandi",
        "ledante", "undi", "cheyyandi",
    ),
    "mr": (
        "tumche", "tumcha", "tumchya", "kara ", "pathva", "tabadtob", "paise",
        "khate", "aahe", "nahitar", "krupaya",
    ),
}

# Scam vocabulary per language. Weights mirror the English scale in scam_detector
# (1 = weak context word, 4 = near-certain fraud signal).
SCAM_LEXICON: Dict[str, Dict[str, int]] = {
    "hi": {
        # Devanagari
        "खाता": 1, "खाते": 1, "बैंक": 1, "बंद": 2, "ब्लॉक": 2, "निलंबित": 2,
        "सत्यापन": 2, "सत्यापित": 2, "ओटीपी": 4, "केवाईसी": 3, "पिन": 3,
        "तुरंत": 2, "जल्दी": 2, "आज ही": 1, "अंतिम चेतावनी": 3,
        "लिंक": 2, "क्लिक": 2, "इनाम": 2, "लॉटरी": 2, "पुरस्कार": 2,
        "जुर्माना": 2, "पुलिस": 2, "गिरफ्तार": 3, "वारंट": 3, "कस्टम": 2,
        "पैसे": 1, "रुपये": 1, "भेजें": 2, "भेजो": 2, "ट्रांसफर": 2,
        "रिफंड": 2, "धनवापसी": 2, "कैशबैक": 2, "आधार": 2, "पैन": 2,
        # Romanized / code-mixed
        "band ho jayega": 4, "band ho jaega": 4, "block ho jayega": 4,
        "khata band": 4, "account band": 4, "otp bhejo": 4, "otp batao": 4,
        "kyc update": 3, "kyc karo": 3, "kyc pending": 3, "verify karo": 3,
        "link par click": 3, "paise bhejo": 3, "turant": 2, "jurmana": 2,
        "giraftar": 3, "inaam": 2, "lottery jeeta": 3, "aadhaar link": 2,
        "pin batao": 4, "upi id bhejo": 4,
    },
    "bn": {
        "অ্যাকাউন্ট": 1, "একাউন্ট": 1, "ব্যাংক": 1, "ব্যাঙ্ক": 1, "বন্ধ": 2, "ব্লক": 2,
        "যাচাই": 2, "ওটিপি": 4, "কেওয়াইসি": 3, "পিন": 3,
        "এখনই": 2, "তাড়াতাড়ি": 2, "শেষ সতর্কতা": 3,
        "লিঙ্ক": 2, "ক্লিক": 2, "পুরস্কার": 2, "লটারি": 2,
        "জরিমানা": 2, "পুলিশ": 2, "গ্রেপ্তার": 3,
        "টাকা": 1, "পাঠান": 2, "পাঠাও": 2, "ফেরত": 2, "আধার": 2,
        "account bondho": 4, "bondho hoye jabe": 4, "otp pathan": 4,
        "taka pathan": 3, "kyc korun": 3, "ekhoni korun": 2, "puroskar": 2,
    },
    "ta": {
        "கணக்கு": 1, "வங்கி": 1, "முடக்கம்": 2, "முடக்கப்படும்": 3, "தடை": 2,
        "சரிபார்ப்பு": 2, "சரிபார்க்க": 2, "ஓடிபி": 4, "கேஒய்சி": 3, "பின்": 3,
        "உடனடியாக": 2, "விரைவாக": 2, "இறுதி எச்சரிக்கை": 3,
        "இணைப்பு": 2, "கிளிக்": 2, "பரிசு": 2, "லாட்டரி": 2,
        "அபராதம்": 2, "காவல்துறை": 2, "கைது": 3,
        "பணம்": 1, "அனுப்பு": 2, "அனுப்பவும்": 2, "பணத்தை": 1, "ஆதார்": 2,
        "kanakku mudakkam": 4, "otp anuppu": 4, "panam anuppu": 3,
        "kyc seiyavum": 3, "udanadiyaga": 2, "parisu": 2,
    },
    "te": {
        "ఖాతా": 1, "బ్యాంకు": 1, "బ్యాంక్": 1, "బ్లాక్": 2, "నిలిపివేత": 2,
        "ధృవీకరణ": 2, "ఓటీపీ": 4, "కేవైసీ": 3, "పిన్": 3,
        "వెంటనే": 2, "త్వరగా": 2, "చివరి హెచ్చరిక": 3,
        "లింక్": 2, "క్లిక్": 2, "బహుమతి": 2, "లాటరీ": 2,
        "జరిమానా": 2, "పోలీసు": 2, "అరెస్ట్": 3,
        "డబ్బు": 1, "పంపండి": 2, "పంపు": 2, "ఆధార్": 2,
        "khata block": 4, "otp pampandi": 4, "dabbu pampandi": 3,
        "kyc cheyandi": 3, "ventane": 2, "bahumati": 2,
    },
    "mr": {
        "खाते": 1, "बँक": 1, "बंद": 2, "ब्लॉक": 2, "निलंबित": 2,
        "पडताळणी": 2, "ओटीपी": 4, "केवायसी": 3, "पिन": 3,
        "ताबडतोब": 2, "लवकर": 2, "अंतिम इशारा": 3,
        "दुवा": 2, "लिंक": 2, "क्लिक": 2, "बक्षीस": 2, "लॉटरी": 2,
        "दंड": 2, "पोलीस": 2, "अटक": 3,
        "पैसे": 1, "पाठवा": 2, "परतावा": 2, "आधार": 2,
        "khate band": 4, "otp pathva": 4, "paise pathva": 3,
        "kyc kara": 3, "tabadtob": 2, "bakshis": 2,
    },
}

# Category hints keyed off vernacular terms, so a Hindi-only message still classifies.
_CATEGORY_TERMS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("KYC_FRAUD", ("केवाईसी", "কেওয়াইসি", "கேஒய்சி", "కేవైసీ", "केवायसी", "kyc")),
    (
        "DIGITAL_ARREST",
        (
            "गिरफ्तार", "वारंट", "গ্রেপ্তার", "கைது", "అరెస్ట్", "अटक",
            "giraftar", "digital arrest", "warrant",
        ),
    ),
    (
        "LOTTERY_SCAM",
        ("इनाम", "लॉटरी", "पुरस्कार", "পুরস্কার", "লটারি", "பரிசு", "லாட்டரி", "బహుమతి", "లాటరీ", "बक्षीस", "inaam", "puroskar", "parisu", "bahumati"),
    ),
    (
        "REFUND_SCAM",
        ("रिफंड", "धनवापसी", "कैशबैक", "ফেরত", "அபராதம்", "परतावा", "refund"),
    ),
    ("UPI_FRAUD", ("यूपीआई", "upi", "paise bhejo", "taka pathan", "panam anuppu", "dabbu pampandi", "paise pathva","पैसे भेजें", "टাকা পাঠান", "பணம் அனுப்பு", "డబ్బు పంపండి", "पैसे पाठवा")),
    (
        "BANK_FRAUD",
        (
            "खाता", "खाते", "बैंक", "बँक", "অ্যাকাউন্ট", "ব্যাংক", "கணக்கு", "வங்கி",
            "ఖాతా", "బ్యాంకు",
            "khata", "khate", "kanakku", "account band", "account bondho",
            "khate band", "khata block", "khata band",
            "otp bhejo", "otp batao", "otp pathan", "otp pathva", "otp anuppu", "otp pampandi",
        ),
    ),
)


@dataclass(frozen=True)
class LanguageResult:
    code: str
    name: str
    confidence: float
    script: str
    romanized: bool


@dataclass(frozen=True)
class MultilingualScanResult:
    score: int
    matched_terms: List[str]
    languages_hit: List[str]
    category_hint: Optional[str]


def _script_of(text: str) -> Tuple[str, float]:
    """Dominant non-Latin Indic script and the share of letters written in it."""
    counts: Dict[str, int] = {}
    letters = 0
    for ch in text:
        if not ch.isalpha():
            continue
        letters += 1
        code = ord(ch)
        for lo, hi, name in _SCRIPT_RANGES:
            if lo <= code <= hi:
                counts[name] = counts.get(name, 0) + 1
                break
    if not counts or letters == 0:
        return "latin", 0.0
    script, hits = max(counts.items(), key=lambda kv: kv[1])
    return script, hits / letters


def _devanagari_language(text: str) -> Tuple[str, float]:
    marathi = sum(1 for m in _MARATHI_MARKERS if m in text)
    hindi = sum(1 for m in _HINDI_MARKERS if m in text)
    if marathi > hindi:
        return "mr", min(0.95, 0.7 + 0.05 * marathi)
    if hindi > marathi:
        return "hi", min(0.95, 0.7 + 0.05 * hindi)
    # No disambiguating marker: Hindi is far more common on Indian scam channels.
    return "hi", 0.6


def _romanized_language(lowered: str) -> Tuple[Optional[str], float, int]:
    best_lang: Optional[str] = None
    best_hits = 0
    for lang, markers in _ROMAN_MARKERS.items():
        hits = sum(1 for m in markers if m in lowered)
        if hits > best_hits:
            best_lang, best_hits = lang, hits
    if not best_lang or best_hits == 0:
        return None, 0.0, 0
    return best_lang, min(0.9, 0.45 + 0.15 * best_hits), best_hits


def detect_language(text: str) -> LanguageResult:
    if not text or not text.strip():
        return LanguageResult(code="unknown", name="Unknown", confidence=0.0, script="none", romanized=False)

    normalized = unicodedata.normalize("NFC", text)
    script, share = _script_of(normalized)

    if script != "latin" and share >= 0.15:
        if script == "devanagari":
            code, confidence = _devanagari_language(normalized)
        else:
            code = _SCRIPT_TO_LANG.get(script, "unknown")
            confidence = min(0.98, 0.7 + share * 0.3)
        return LanguageResult(
            code=code,
            name=LANGUAGE_NAMES.get(code, "Unknown"),
            confidence=round(confidence, 2),
            script=script,
            romanized=False,
        )

    code, confidence, hits = _romanized_language(normalized.lower())
    if code:
        return LanguageResult(
            code=code,
            name=LANGUAGE_NAMES[code],
            confidence=round(confidence, 2),
            script="latin",
            romanized=True,
        )

    return LanguageResult(code="en", name="English", confidence=0.6, script="latin", romanized=False)


def _compile_patterns() -> Dict[str, List[Tuple[re.Pattern, str, int]]]:
    """Word-boundary patterns for Latin terms, plain substring for Indic scripts."""
    compiled: Dict[str, List[Tuple[re.Pattern, str, int]]] = {}
    for lang, terms in SCAM_LEXICON.items():
        entries = []
        for term, weight in terms.items():
            if term.isascii():
                pattern = re.compile(r"(?<![a-z])" + re.escape(term) + r"(?![a-z])", re.IGNORECASE)
            else:
                pattern = re.compile(re.escape(term))
            entries.append((pattern, term, weight))
        compiled[lang] = entries
    return compiled


_PATTERNS = _compile_patterns()


def scan(text: str) -> MultilingualScanResult:
    """
    Score a message against every vernacular lexicon at once.

    Every language is scanned regardless of detected language, because code-mixed
    messages ("KYC pending hai, turant update karo") belong to two lexicons.
    """
    if not text:
        return MultilingualScanResult(score=0, matched_terms=[], languages_hit=[], category_hint=None)

    normalized = unicodedata.normalize("NFC", text)
    score = 0
    matched: List[str] = []
    languages: List[str] = []

    for lang, entries in _PATTERNS.items():
        lang_hit = False
        for pattern, term, weight in entries:
            if pattern.search(normalized):
                # A term shared across lexicons (e.g. "बंद" in hi and mr) scores once.
                if term not in matched:
                    score += weight
                    matched.append(term)
                lang_hit = True
        if lang_hit:
            languages.append(lang)

    lowered = normalized.lower()
    category = None
    for name, terms in _CATEGORY_TERMS:
        if any(t in lowered or t in normalized for t in terms):
            category = name
            break

    return MultilingualScanResult(
        score=score,
        matched_terms=sorted(matched),
        languages_hit=sorted(languages),
        category_hint=category,
    )


def reply_language_instruction(language_code: str) -> str:
    """Tells the reply LLM which language to answer in, so the persona stays believable."""
    if language_code in {"en", "unknown", ""}:
        return "Reply in simple English."
    name = LANGUAGE_NAMES.get(language_code, "English")
    return (
        f"The scammer is writing in {name}. Reply in {name} using the same script they used "
        f"(if they wrote {name} in Latin letters, reply in Latin letters too). "
        "Match their register - an ordinary person texting, not a translator."
    )


def _self_check() -> None:
    assert detect_language("आपका खाता बंद हो जाएगा").code == "hi"
    assert detect_language("तुमचे खाते बंद होईल, ताबडतोब पाठवा").code == "mr"
    assert detect_language("আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে").code == "bn"
    assert detect_language("உங்கள் கணக்கு முடக்கப்படும்").code == "ta"
    assert detect_language("మీ ఖాతా బ్లాక్ అవుతుంది").code == "te"
    assert detect_language("aapka account band ho jayega").code == "hi"
    assert detect_language("aapka account band ho jayega").romanized is True
    assert detect_language("Your account will be blocked").code == "en"
    assert detect_language("").code == "unknown"

    # The headline case from the feature spec must score like its English twin.
    hindi = scan("aapka account band ho jayega, turant otp bhejo")
    assert hindi.score >= 8, hindi
    assert hindi.category_hint in {"BANK_FRAUD", "KYC_FRAUD", "UPI_FRAUD"}, hindi

    native = scan("आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें")
    assert native.score >= 8, native

    # Code-mixed hits more than one lexicon.
    mixed = scan("Your KYC pending hai, turant update karo")
    assert "hi" in mixed.languages_hit, mixed
    assert mixed.category_hint == "KYC_FRAUD", mixed

    # Clean English business text must not trip the vernacular lexicon.
    assert scan("Let us meet for lunch tomorrow").score == 0

    assert "Hindi" in reply_language_instruction("hi")
    assert "English" in reply_language_instruction("en")
    print("multilingual self-check ok")


if __name__ == "__main__":
    _self_check()
