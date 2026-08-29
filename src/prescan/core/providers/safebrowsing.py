"""Google Safe Browsing provider (URL reputation).

Implemented on M3 with the §7 URL pipeline.

PRIVACY REQUIREMENT (§6.2): use the **hash-prefix** mechanism — the Update API
v4 (local hash-prefix database) or the Search API v5 (send only truncated
SHA-256 prefixes, confirm full-length matches locally). Do **NOT** use the
Lookup API: it sends the full URL to Google, which violates the privacy
principle. Keyring id: ``safebrowsing``. Free tier is non-commercial only.
"""

from __future__ import annotations
