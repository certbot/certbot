# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (C) 2013 Association of Universities for Research in Astronomy
#                    (AURA)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
#     3. The name of AURA and its representatives may not be used to
#        endorse or promote products derived from this software without
#        specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY AURA ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AURA BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

import logging
import os
import sys
import warnings

from distutils import errors

from pbr import util


if sys.version_info[0] == 3:
    string_type = str
    integer_types = (int,)
else:
    string_type = basestring  # noqa
    integer_types = (int, long)  # noqa


def pbr(dist, attr, value):
    """Implements the actual pbr setup() keyword.

    When used, this should be the only keyword in your setup() aside from
    `setup_requires`.

    If given as a string, the value of pbr is assumed to be the relative path
    to the setup.cfg file to use.  Otherwise, if it evaluates to true, it
    simply assumes that pbr should be used, and the default 'setup.cfg' is
    used.

    This works by reading the setup.cfg file, parsing out the supported
    metadata and command options, and using them to rebuild the
    `DistributionMetadata` object and set the newly added command options.

    The reason for doing things this way is that a custom `Distribution` class
    will not play nicely with setup_requires; however, this implementation may
    not work well with distributions that do use a `Distribution` subclass.
    """

    if not value:
        return
    if isinstance(value, string_type):
        path = os.path.abspath(value)
    else:
        path = os.path.abspath('setup.cfg')
    if not os.path.exists(path):
        raise errors.DistutilsFileError(
            'The setup.cfg file %s does not exist.' % path)

    # Converts the setup.cfg file to setup() arguments
    try:
        attrs = util.cfg_to_args(path, dist.script_args)
    except Exception:
        e = sys.exc_info()[1]
        # NB: This will output to the console if no explicit logging has
        # been setup - but thats fine, this is a fatal distutils error, so
        # being pretty isn't the #1 goal.. being diagnosable is.
        logging.exception('Error parsing')
        raise errors.DistutilsSetupError(
            'Error parsing %s: %s: %s' % (path, e.__class__.__name__, e))

    # There are some metadata fields that are only supported by
    # setuptools and not distutils, and hence are not in
    # dist.metadata.  We are OK to write these in.  For gory details
    # see
    #  https://github.com/pypa/setuptools/pull/1343
    _DISTUTILS_UNSUPPORTED_METADATA = (
        'long_description_content_type', 'project_urls', 'provides_extras'
    )

    # Repeat some of the Distribution initialization code with the newly
    # provided attrs
    if attrs:
        # Skips 'options' and 'licence' support which are rarely used; may
        # add back in later if demanded
        for key, val in attrs.items():
            if hasattr(dist.metadata, 'set_' + key):
                getattr(dist.metadata, 'set_' + key)(val)
            elif hasattr(dist.metadata, key):
                setattr(dist.metadata, key, val)
            elif hasattr(dist, key):
                setattr(dist, key, val)
            elif key in _DISTUTILS_UNSUPPORTED_METADATA:
                setattr(dist.metadata, key, val)
            else:
                msg = 'Unknown distribution option: %s' % repr(key)
                warnings.warn(msg)

    # Re-finalize the underlying Distribution
    try:
        super(dist.__class__, dist).finalize_options()
    except TypeError:
        # If dist is not declared as a new-style class (with object as
        # a subclass) then super() will not work on it. This is the case
        # for Python 2. In that case, fall back to doing this the ugly way
        dist.__class__.__bases__[-1].finalize_options(dist)

    # This bit comes out of distribute/setuptools
    if isinstance(dist.metadata.version, integer_types + (float,)):
        # Some people apparently take "version number" too literally :)
        dist.metadata.version = str(dist.metadata.version)
