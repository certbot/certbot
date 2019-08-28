""" Tests for ParserNode utils """
import unittest

from certbot_apache.tests import parsernode_test


class ParserNodeUtilTest(unittest.TestCase):
    """Tests for ParserNode utils"""
    def test_unknown_parameter(self):
        params = {
            "comment": "x",
            "ancestor": None,
            "dirty": False,
            "filepath": "/tmp",
            "unknown": "x"
        }
        self.assertRaises(TypeError, parsernode_test.DummyCommentNode, **params)
        params["name"] = "unnamed"
        params.pop("comment")
        self.assertRaises(TypeError, parsernode_test.DummyDirectiveNode, **params)
        self.assertRaises(TypeError, parsernode_test.DummyBlockNode, **params)

    def test_missing_required(self):
        params = {
            "ancestor": None,
            "dirty": False,
            "filepath": "/tmp",
        }
        self.assertRaises(TypeError, parsernode_test.DummyCommentNode, **params)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
