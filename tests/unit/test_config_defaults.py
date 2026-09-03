"""Privacy defaults are load-bearing, so pin them.

only_send_hashes defaults OFF: a URL scan is an explicit action on a user-typed URL
and the Privacy screen names who receives it beforehand, so a link can clear to SAFE
out of the box. never_upload_files defaults ON: it is the real §10.5 guard and must
never ship off. Pure model defaults -- no I/O, no network.
"""

from __future__ import annotations

from prescan.core.config import AppConfig


def test_privacy_toggle_defaults() -> None:
    config = AppConfig()
    assert config.only_send_hashes is False
    assert config.never_upload_files is True
