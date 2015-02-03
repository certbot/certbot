"""Let's Encrypt user-supplied configuration."""
import zope.interface

from letsencrypt.client import interfaces


class NamespaceConfig(object):
    """Configuration wrapper around `argparse.Namespace`."""
    zope.interface.implements(interfaces.IConfig)

    def __init__(self, namespace):
        self.namespace = namespace

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    @property
    def temp_checkpoint_dir(self):
        return os.path.join(
            self.namespace.work_dir, constants.TEMP_CHECKPOINT_DIR_NAME)

    @property
    def in_progress_dir(self):
        return os.path.join(
            self.namespace.work_dir, constants.IN_PROGRESS_DIR_NAME)

    @property
    def cert_key_backup(self):
        return os.path.join(
            self.namespace.work_dir, constants.CERT_KEY_BACKUP_DIR_NAME)

    @property
    def rev_tokens_dir(self):
        return os.path.join(
            self.namespace.work_dir, constants.REV_TOKENS_DIR_NAME)
