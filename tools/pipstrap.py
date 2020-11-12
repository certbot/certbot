#!/usr/bin/env python
"""Uses pip to upgrade Python packaging tools to pinned versions."""
from __future__ import absolute_import

import os
import shutil
import tempfile

import pip_install


# We include the hashes of the packages here for extra verification of
# the packages downloaded from PyPI. This is especially valuable in our
# builds of Certbot that we ship to our users such as our Docker images.
#
# An older version of setuptools is currently used here in order to keep
# compatibility with Python 2 since newer versions of setuptools have dropped
# support for it.
REQUIREMENTS = r"""
pip==20.2.4 \
    --hash=sha256:51f1c7514530bd5c145d8f13ed936ad6b8bfcb8cf74e10403d0890bc986f0033 \
    --hash=sha256:85c99a857ea0fb0aedf23833d9be5c40cf253fe24443f0829c7b472e23c364a1
setuptools==44.1.1 \
    --hash=sha256:27a714c09253134e60a6fa68130f78c7037e5562c4f21f8f318f2ae900d152d5 \
    --hash=sha256:c67aa55db532a0dadc4d2e20ba9961cbd3ccc84d544e9029699822542b5a476b
wheel==0.35.1 \
    --hash=sha256:497add53525d16c173c2c1c733b8f655510e909ea78cc0e29d374243544b77a2 \
    --hash=sha256:99a22d87add3f634ff917310a3d87e499f19e663413a52eb9232c447aa646c9f
"""


def main():
    with pip_install.temporary_directory() as tempdir:
        requirements_filepath = os.path.join(tempdir, 'reqs.txt')
        with open(requirements_filepath, 'w') as f:
            f.write(REQUIREMENTS)
        pip_install_args = '--requirement ' + requirements_filepath
        # We don't disable build isolation because we may have an older
        # version of pip that doesn't support the flag disabling it. We
        # expect these packages to already have usable wheels available
        # anyway so no building should be required.
        pip_install.pip_install_with_print(pip_install_args,
                                           disable_build_isolation=False)


if __name__ == '__main__':
    main()
