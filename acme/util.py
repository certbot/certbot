"""ACME utilities."""
import json
import pkg_resources


def load_schema(name):
    """Load JSON schema from distribution."""
    return json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % name)))
