"""Tests for josepy.interfaces."""
import unittest


class JSONDeSerializableTest(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes

    def setUp(self):
        from josepy.interfaces import JSONDeSerializable

        # pylint: disable=missing-docstring,invalid-name

        class Basic(JSONDeSerializable):
            def __init__(self, v):
                self.v = v

            def to_partial_json(self):
                return self.v

            @classmethod
            def from_json(cls, jobj):
                return cls(jobj)

        class Sequence(JSONDeSerializable):
            def __init__(self, x, y):
                self.x = x
                self.y = y

            def to_partial_json(self):
                return [self.x, self.y]

            @classmethod
            def from_json(cls, jobj):
                return cls(
                    Basic.from_json(jobj[0]), Basic.from_json(jobj[1]))

        class Mapping(JSONDeSerializable):
            def __init__(self, x, y):
                self.x = x
                self.y = y

            def to_partial_json(self):
                return {self.x: self.y}

            @classmethod
            def from_json(cls, jobj):
                pass  # pragma: no cover

        self.basic1 = Basic('foo1')
        self.basic2 = Basic('foo2')
        self.seq = Sequence(self.basic1, self.basic2)
        self.mapping = Mapping(self.basic1, self.basic2)
        self.nested = Basic([[self.basic1]])
        self.tuple = Basic(('foo',))

        # pylint: disable=invalid-name
        self.Basic = Basic
        self.Sequence = Sequence
        self.Mapping = Mapping

    def test_to_json_sequence(self):
        self.assertEqual(self.seq.to_json(), ['foo1', 'foo2'])

    def test_to_json_mapping(self):
        self.assertEqual(self.mapping.to_json(), {'foo1': 'foo2'})

    def test_to_json_other(self):
        mock_value = object()
        self.assertTrue(self.Basic(mock_value).to_json() is mock_value)

    def test_to_json_nested(self):
        self.assertEqual(self.nested.to_json(), [['foo1']])

    def test_to_json(self):
        self.assertEqual(self.tuple.to_json(), (('foo', )))

    def test_from_json_not_implemented(self):
        from josepy.interfaces import JSONDeSerializable
        self.assertRaises(TypeError, JSONDeSerializable.from_json, 'xxx')

    def test_json_loads(self):
        seq = self.Sequence.json_loads('["foo1", "foo2"]')
        self.assertTrue(isinstance(seq, self.Sequence))
        self.assertTrue(isinstance(seq.x, self.Basic))
        self.assertTrue(isinstance(seq.y, self.Basic))
        self.assertEqual(seq.x.v, 'foo1')
        self.assertEqual(seq.y.v, 'foo2')

    def test_json_dumps(self):
        self.assertEqual('["foo1", "foo2"]', self.seq.json_dumps())

    def test_json_dumps_pretty(self):
        self.assertEqual(self.seq.json_dumps_pretty(),
                         '[\n    "foo1",\n    "foo2"\n]')

    def test_json_dump_default(self):
        from josepy.interfaces import JSONDeSerializable

        self.assertEqual(
            'foo1', JSONDeSerializable.json_dump_default(self.basic1))

        jobj = JSONDeSerializable.json_dump_default(self.seq)
        self.assertEqual(len(jobj), 2)
        self.assertTrue(jobj[0] is self.basic1)
        self.assertTrue(jobj[1] is self.basic2)

    def test_json_dump_default_type_error(self):
        from josepy.interfaces import JSONDeSerializable
        self.assertRaises(
            TypeError, JSONDeSerializable.json_dump_default, object())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
