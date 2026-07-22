"""
Shared Hypothesis strategies for ClamUI property tests.

These composite strategies generate adversarial inputs targeted at the
security-sensitive modules under test (sanitize, path_validation,
threat_classifier, scheduler). Keeping them in one place encourages reuse
and makes it easy to tighten coverage centrally.
"""

from __future__ import annotations

import string

from hypothesis import strategies as st

ANSI_FRAGMENTS = [
    "\x1b[31m",
    "\x1b[0m",
    "\x1b[1;32m",
    "\x1b[?25h",
    "\x1b[H",
    "\x1bP",
]

BIDI_CHARS = [
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
]

CONTROL_CHARS = [chr(c) for c in range(0x00, 0x20) if c not in (0x09,)] + ["\x7f"]

SHELL_METACHARS = [";", "&&", "||", "|", "`", "$(", ")", ">", "<", "*", "?", "'", '"']


@st.composite
def adversarial_text(draw: st.DrawFn) -> str:
    """
    Build a string with random mixes of ANSI escapes, bidi overrides,
    control characters, surrogates, and ordinary text.
    """
    pieces = draw(
        st.lists(
            st.one_of(
                st.text(max_size=20),
                st.sampled_from(ANSI_FRAGMENTS),
                st.sampled_from(BIDI_CHARS),
                st.sampled_from(CONTROL_CHARS),
                st.text(
                    alphabet=st.characters(min_codepoint=0, max_codepoint=0x1F),
                    max_size=5,
                ),
            ),
            max_size=12,
        )
    )
    return "".join(pieces)


@st.composite
def surrogate_text(draw: st.DrawFn) -> str:
    """
    Text that may contain lone surrogate code points (U+D800-U+DFFF).
    These typically arise from surrogateescape-decoded non-UTF-8 filenames.
    """
    parts = draw(
        st.lists(
            st.one_of(
                st.text(max_size=10),
                st.text(
                    alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF),
                    max_size=3,
                ),
            ),
            max_size=6,
        )
    )
    return "".join(parts)


@st.composite
def injection_path(draw: st.DrawFn) -> str:
    """
    Filesystem-path-like strings that may include injection payloads:
    newlines, null bytes, shell metacharacters, and control chars.
    """
    parts = draw(
        st.lists(
            st.one_of(
                st.text(
                    alphabet=string.ascii_letters + string.digits + "/._-",
                    min_size=1,
                    max_size=15,
                ),
                st.sampled_from(["\n", "\r", "\x00"]),
                st.sampled_from(SHELL_METACHARS),
            ),
            min_size=1,
            max_size=6,
        )
    )
    return "".join(parts)


SAFE_PATH_ALPHABET = string.ascii_letters + string.digits + "/._- "


@st.composite
def safe_path(draw: st.DrawFn) -> str:
    """
    Paths that should always pass scheduler validation:
    printable chars only, no newlines, no carriage returns, no null bytes.
    """
    text = draw(st.text(alphabet=SAFE_PATH_ALPHABET, min_size=1, max_size=50))
    return text


THREAT_VENDORS = ["Win", "Unix", "Osx", "Html", "Doc", "Xls", "Java", "Js"]
THREAT_FAMILIES = [
    "Agent",
    "Generic",
    "Locky",
    "Emotet",
    "Downloader",
    "Zbot",
    "Kraken",
]
# Substrings that classify_threat_severity / categorize_threat recognize.
KNOWN_SEVERITY_PATTERNS = [
    # Critical
    "ransom",
    "rootkit",
    "bootkit",
    "cryptolocker",
    "wannacry",
    # High
    "trojan",
    "worm",
    "backdoor",
    "exploit",
    "downloader",
    "dropper",
    "keylogger",
    # Medium
    "adware",
    "pua",
    "pup",
    "spyware",
    "miner",
    "coinminer",
    # Low
    "eicar",
    "test-signature",
    "test.file",
    "heuristic",
    "generic",
]

KNOWN_CATEGORY_PATTERNS = [
    "ransomware",
    "ransom",
    "rootkit",
    "bootkit",
    "trojan",
    "worm",
    "backdoor",
    "exploit",
    "adware",
    "spyware",
    "keylogger",
    "eicar",
    "test-signature",
    "test.file",
    "macro",
    "phish",
    "heuristic",
    "pua",
    "pup",
    "virus",
]


@st.composite
def threat_name(draw: st.DrawFn) -> str:
    """
    Threat names built from realistic ClamAV patterns with random casing.
    """
    vendor = draw(st.sampled_from(THREAT_VENDORS))
    pattern = draw(st.sampled_from(KNOWN_SEVERITY_PATTERNS))
    family = draw(st.sampled_from(THREAT_FAMILIES))
    sep = draw(st.sampled_from([".", "-"]))

    name = f"{vendor}{sep}{pattern}{sep}{family}"

    # Randomly re-case characters so callers can compare case-insensitivity.
    swap = draw(st.lists(st.booleans(), min_size=len(name), max_size=len(name)))
    return "".join(c.upper() if s else c.lower() for c, s in zip(name, swap, strict=True))


UNKNOWN_ALPHABET = string.ascii_letters + string.digits + "._-"


@st.composite
def unknown_threat_name(draw: st.DrawFn) -> str:
    """
    Random names that contain no classifier or category pattern. The caller
    can therefore assert defaults (severity MEDIUM, category "Virus").
    """
    name = draw(st.text(alphabet=UNKNOWN_ALPHABET, min_size=1, max_size=30))
    lowered = name.lower()
    all_patterns = set(KNOWN_SEVERITY_PATTERNS) | set(KNOWN_CATEGORY_PATTERNS)
    for pattern in all_patterns:
        if pattern in lowered:
            # Redraw rather than filter to avoid Hypothesis shrinking oddities.
            return "unrecognised"
    return name
