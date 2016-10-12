"""ACME utilities."""
import pkg_resources
import six

from acme import errors


def map_keys(dikt, func):
    """Map dictionary keys."""
    return dict((func(key), value) for key, value in six.iteritems(dikt))


def activate(requirement):
    """Make requirement importable.

    :param str requirement: the distribution and version to activate

    :raises acme.errors.DependencyError: if cannot activate requirement

    """
    try:
        for distro in pkg_resources.require(requirement):  # pylint: disable=not-callable
            distro.activate()
    except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
        raise errors.DependencyError('{0} is unavailable'.format(requirement))
