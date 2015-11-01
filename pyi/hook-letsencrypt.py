"""PyInstaller hook for Let's Encrypt client."""
import pkg_resources

from letsencrypt import constants
from PyInstaller.hooks.hookutils import collect_data_files


#datas = collect_data_files('letsencrypt')
datas = [
    ('../letsencrypt/DISCLAIMER', 'letsencrypt'),
]

hiddenimports = [
    ep.module_name for ep in pkg_resources.iter_entry_points(
        constants.SETUPTOOLS_PLUGINS_ENTRY_POINT)]
