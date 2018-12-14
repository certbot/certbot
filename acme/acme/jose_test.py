"""Tests for acme.jose shim."""
import importlib
import unittest

class JoseTest(unittest.TestCase):
    """Tests for acme.jose shim."""

    def _test_it(self, submodule, attribute):
        if submodule:
            acme_jose_path = 'acme.jose.' + submodule
            josepy_path = 'josepy.' + submodule
        else:
            acme_jose_path = 'acme.jose'
            josepy_path = 'josepy'
        acme_jose = importlib.import_module(acme_jose_path)
        josepy = importlib.import_module(josepy_path)

        self.assertIs(acme_jose, josepy)
        self.assertIs(getattr(acme_jose, attribute), getattr(josepy, attribute))

    def test_top_level(self):
        self._test_it('', 'RS512')

    def test_submodules(self):
        # This test ensures that the modules in josepy that were
        # available at the time it was moved into its own package are
        # available under acme.jose. Backwards compatibility with new
        # modules or testing code is not maintained.
        mods_and_attrs = [('b64', 'b64decode',),
                          ('errors', 'Error',),
                          ('interfaces', 'JSONDeSerializable',),
                          ('json_util', 'Field',),
                          ('jwa', 'HS256',),
                          ('jwk', 'JWK',),
                          ('jws', 'JWS',),
                          ('util', 'ImmutableMap',),]

        for mod, attr in mods_and_attrs:
            self._test_it(mod, attr)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
