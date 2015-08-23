"""PyInstaller hook for cryptography."""
import pkg_resources

hiddenimports = [
    ep.module_name for ep in pkg_resources.iter_entry_points(
        'cryptography.backends')]
