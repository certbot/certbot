"""Plugin storage class."""
import json
import logging
from typing import Any

from certbot import configuration
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os

logger = logging.getLogger(__name__)


class PluginStorage:
    """Class implementing storage functionality for plugins"""

    def __init__(self, config: configuration.NamespaceConfig, classkey: str) -> None:
        """Initializes PluginStorage object storing required configuration
        options.

        :param .configuration.NamespaceConfig config: Configuration object
        :param str classkey: class name to use as root key in storage file

        """

        self._config = config
        self._classkey = classkey
        self._initialized = False
        self._data: dict
        self._storagepath: str

    def _initialize_storage(self) -> None:
        """Initializes PluginStorage data and reads current state from the disk
        if the storage json exists."""

        self._storagepath = os.path.join(self._config.config_dir, ".pluginstorage.json")
        self._load()
        self._initialized = True

    def _load(self) -> None:
        """Reads PluginStorage content from the disk to a dict structure

        :raises .errors.PluginStorageError: when unable to open or read the file
        """
        data: dict[str, Any] = {}
        filedata = ""
        try:
            with open(self._storagepath, 'r') as fh:
                filedata = fh.read()
        except OSError as e:
            errmsg = "Could not read PluginStorage data file: {0} : {1}".format(
                self._storagepath, str(e))
            if os.path.isfile(self._storagepath):
                # Only error out if file exists, but cannot be read
                logger.error(errmsg)
                raise errors.PluginStorageError(errmsg)
        try:
            data = json.loads(filedata)
        except ValueError:
            if not filedata:
                logger.debug("Plugin storage file %s was empty, no values loaded",
                             self._storagepath)
            else:
                errmsg = "PluginStorage file {0} is corrupted.".format(
                    self._storagepath)
                logger.error(errmsg)
                raise errors.PluginStorageError(errmsg)
        self._data = data

    def save(self) -> None:
        """Saves PluginStorage content to disk

        :raises .errors.PluginStorageError: when unable to serialize the data
            or write it to the filesystem
        """
        if not self._initialized:
            errmsg = "Unable to save, no values have been added to PluginStorage."
            logger.error(errmsg)
            raise errors.PluginStorageError(errmsg)

        try:
            serialized = json.dumps(self._data)
        except TypeError as e:
            errmsg = "Could not serialize PluginStorage data: {0}".format(
                str(e))
            logger.error(errmsg)
            raise errors.PluginStorageError(errmsg)
        try:
            with os.fdopen(filesystem.open(
                    self._storagepath,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600), 'w') as fh:
                fh.write(serialized)
        except OSError as e:
            errmsg = "Could not write PluginStorage data to file {0} : {1}".format(
                self._storagepath, str(e))
            logger.error(errmsg)
            raise errors.PluginStorageError(errmsg)

    def put(self, key: str, value: Any) -> None:
        """Put configuration value to PluginStorage

        :param str key: Key to store the value to
        :param value: Data to store
        """
        if not self._initialized:
            self._initialize_storage()

        if self._classkey not in self._data:
            self._data[self._classkey] = {}
        self._data[self._classkey][key] = value

    def fetch(self, key: str) -> Any:
        """Get configuration value from PluginStorage

        :param str key: Key to get value from the storage

        :raises KeyError: If the key doesn't exist in the storage
        """
        if not self._initialized:
            self._initialize_storage()

        return self._data[self._classkey][key]
