""" Tests for ParserNode utils """
import unittest

from certbot_apache import parsernode_util as util


class ParserNodeUtilTest(unittest.TestCase):
    """Tests for ParserNode utils"""

    def _setup_parsernode(self):
        """ Sets up kwargs dict for ParserNode """
        return {
            "ancestor": None,
            "dirty": False,
            "filepath": "/tmp",
        }

    def _setup_commentnode(self):
        """ Sets up kwargs dict for CommentNode """

        pn = self._setup_parsernode()
        pn["comment"] = "x"
        return pn

    def _setup_directivenode(self):
        """ Sets up kwargs dict for DirectiveNode """

        pn = self._setup_parsernode()
        pn["name"] = "Name"
        pn["parameters"] = ("first",)
        pn["enabled"] = True
        return pn

    def test_unknown_parameter(self):
        params = self._setup_parsernode()
        params["unknown"] = "unknown"
        self.assertRaises(TypeError, util.parsernode_kwargs, params)

        params = self._setup_commentnode()
        params["unknown"] = "unknown"
        self.assertRaises(TypeError, util.commentnode_kwargs, params)

        params = self._setup_directivenode()
        params["unknown"] = "unknown"
        self.assertRaises(TypeError, util.directivenode_kwargs, params)

    def test_parsernode(self):
        params = self._setup_parsernode()
        ctrl = self._setup_parsernode()

        ancestor, dirty, filepath = util.parsernode_kwargs(params)
        self.assertEqual(ancestor, ctrl["ancestor"])
        self.assertEqual(dirty, ctrl["dirty"])
        self.assertEqual(filepath, ctrl["filepath"])

    def test_commentnode(self):
        params = self._setup_commentnode()
        ctrl = self._setup_commentnode()

        comment, _ = util.commentnode_kwargs(params)
        self.assertEqual(comment, ctrl["comment"])

    def test_directivenode(self):
        params = self._setup_directivenode()
        ctrl = self._setup_directivenode()

        name, parameters, enabled, _ = util.directivenode_kwargs(params)
        self.assertEqual(name, ctrl["name"])
        self.assertEqual(parameters, ctrl["parameters"])
        self.assertEqual(enabled, ctrl["enabled"])

    def test_missing_required(self):
        c_params = self._setup_commentnode()
        c_params.pop("comment")
        self.assertRaises(TypeError, util.commentnode_kwargs, c_params)

        d_params = self._setup_directivenode()
        d_params.pop("ancestor")
        self.assertRaises(TypeError, util.directivenode_kwargs, d_params)

        p_params = self._setup_parsernode()
        p_params.pop("filepath")
        self.assertRaises(TypeError, util.parsernode_kwargs, p_params)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
