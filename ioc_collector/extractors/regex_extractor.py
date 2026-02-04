import re
from typing import Dict, List
from ..utils.defanger import refang
from urllib.parse import urlparse

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b"
)

URL_RE = re.compile(
    r"\bhttps?://[^\s\"\'<>]+|\bhxxps?://[^\s\"\'<>]+",
    re.IGNORECASE
)

EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\])[a-zA-Z0-9.-]+(?:\.|\[.\])[a-zA-Z]{2,}\b"
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

BAD_DOMAIN_SUFFIXES = (".exe", ".dll", ".zip", ".rar", ".7z", ".msi", ".ps1", ".bat", ".cmd", ".scr")

def domains_from_urls(urls):
    out = []
    for u in urls:
        try:
            pu = urlparse(u)
            if pu.hostname:
                out.append(pu.hostname)
        except Exception:
            pass
    return out

def clean_domains(domains):
    cleaned = []
    for d in domains:
        d = d.strip().lower()
        if d.endswith(BAD_DOMAIN_SUFFIXES):
            continue
        if "." not in d:
            continue
        cleaned.append(d)
    return cleaned


def extract_iocs(text: str, do_refang: bool = True, unique: bool = True) -> Dict[str, List[str]]:
    raw = refang(text) if do_refang else text

    iocs = {
        
        "ipv4": IPV4_RE.findall(raw),
        "domains": DOMAIN_RE.findall(raw),
        "urls": URL_RE.findall(raw),
        "emails": EMAIL_RE.findall(text),  # email defang için orijinalde [@] olabilir
        "cves": CVE_RE.findall(raw),
        "mitre_techniques": MITRE_RE.findall(raw),
        "hash_md5": MD5_RE.findall(raw),
        "hash_sha1": SHA1_RE.findall(raw),
        "hash_sha256": SHA256_RE.findall(raw),
    }

    # URL'lerden domain türet, domain listesini temizle
    derived = domains_from_urls(iocs["urls"])
    iocs["domains"].extend(derived)
    iocs["domains"] = clean_domains(iocs["domains"])
    
    # email’i de refang kısmı
    if do_refang:
        iocs["emails"] = [refang(e) for e in iocs["emails"]]

    if unique:
        for k, v in iocs.items():
            seen = []
            for item in v:
                if item not in seen:
                    seen.append(item)
            iocs[k] = seen

    return iocs