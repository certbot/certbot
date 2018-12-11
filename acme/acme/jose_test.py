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

    def test_submodule(self):
        self._test_it('jws', 'JWS')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
