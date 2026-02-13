"""nginx plugin constants."""
import platform
from typing import Any

FREEBSD_DARWIN_SERVER_ROOT = "/usr/local/etc/nginx"
LINUX_SERVER_ROOT = "/etc/nginx"
PKGSRC_SERVER_ROOT = "/usr/pkg/etc/nginx"

if platform.system() in ('FreeBSD', 'Darwin'):
    server_root_tmp = FREEBSD_DARWIN_SERVER_ROOT
elif platform.system() in ('NetBSD',):
    server_root_tmp = PKGSRC_SERVER_ROOT
else:
    server_root_tmp = LINUX_SERVER_ROOT

CLI_DEFAULTS: dict[str, Any] = {
    "server_root": server_root_tmp,
    "ctl": "nginx",
    "sleep_seconds": 1
}
"""CLI defaults."""


MOD_SSL_CONF_DEST = "options-ssl-nginx.conf"
"""Name of the mod_ssl config file as saved
in `certbot.configuration.NamespaceConfig.config_dir`."""

UPDATED_MOD_SSL_CONF_DIGEST = ".updated-options-ssl-nginx-conf-digest.txt"
"""Name of the hash of the updated or informed mod_ssl_conf as saved
in `certbot.configuration.NamespaceConfig.config_dir`."""

ALL_SSL_OPTIONS_HASHES = [
    '0f81093a1465e3d4eaa8b0c14e77b2a2e93568b0fc1351c2b87893a95f0de87c',
    '9a7b32c49001fed4cff8ad24353329472a50e86ade1ef9b2b9e43566a619612e',
    'a6d9f1c7d6b36749b52ba061fff1421f9a0a3d2cfdafbd63c05d06f65b990937',
    '7f95624dd95cf5afc708b9f967ee83a24b8025dc7c8d9df2b556bbc64256b3ff',
    '394732f2bbe3e5e637c3fb5c6e980a1f1b90b01e2e8d6b7cff41dde16e2a756d',
    '4b16fec2bcbcd8a2f3296d886f17f9953ffdcc0af54582452ca1e52f5f776f16',
    'c052ffff0ad683f43bffe105f7c606b339536163490930e2632a335c8d191cc4',
    '02329eb19930af73c54b3632b3165d84571383b8c8c73361df940cb3894dd426',
    '63e2bddebb174a05c9d8a7cf2adf72f7af04349ba59a1a925fe447f73b2f1abf',
    '2901debc7ecbc10917edd9084c05464c9c5930b463677571eaf8c94bffd11ae2',
    '30baca73ed9a5b0e9a69ea40e30482241d8b1a7343aa79b49dc5d7db0bf53b6c',
    '02329eb19930af73c54b3632b3165d84571383b8c8c73361df940cb3894dd426',
    '108c4555058a087496a3893aea5d9e1cee0f20a3085d44a52dc1a66522299ac3',
    'd5e021706ecdccc7090111b0ae9a29ef61523e927f020e410caf0a1fd7063981',
    'ef11e3fb17213e74d3e1816cde0ec37b8b95b4167cf21e7b8ff1eaa9c6f918ee',
    'af85f6193808a44789a1d293e6cffa249cad9a21135940800958b8e3c72dbc69',
    'a2a612fd21b02abaa32d9d11ac63d987d6e3054dbfa356de5800eea0d7ce17f3',
    '2d9648302e3588a172c318e46bff88ade46fc7a16d6afc85322776a04800d473',
    '5e21cc66989f26ec46116d979421e538131cf8ab33ffff3f682fbfe491b0ace8',
    'f5615544105c4eee44f02a604e3e9ae55b3d5bad247160bb18731a0ac531af02',
    '05a799c4db12f8e15e68219c98056824cbd5ae7b05863225318ae112f343880b',
    'dc81acfd9670f137d5abbccfe3438d9306d4b6a906439b0fbf6a6756272e7cc7',
    '0175f71721dd8e5315a6d0f3efef703ff54e867d1ab2a4e076791b89a0b3511a',
    '246b520bedc461fcbd35f4d3efdd75ebf171baccaba5c38f488009566de6d5b3',
    'dd72286f760c90550f34fbeeceb5a1f1351b09b812e65a18569a0f4a4d7f5847',
]
"""SHA256 hashes of the contents of all versions of MOD_SSL_CONF_SRC"""


def os_constant(key: str) -> Any:
    # XXX TODO: In the future, this could return different constants
    #           based on what OS we are running under.  To see an
    #           approach to how to handle different OSes, see the
    #           apache version of this file.  Currently, we do not
    #           actually have any OS-specific constants on Nginx.
    """
    Get a constant value for operating system

    :param str key: name of cli constant
    :return: value of constant for active os
    """
    return CLI_DEFAULTS[key]


HSTS_ARGS = ['\"max-age=31536000\"', ' ', 'always']

HEADER_ARGS = {'Strict-Transport-Security': HSTS_ARGS}
