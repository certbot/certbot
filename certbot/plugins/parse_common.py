"""Common code for plugins that parse configuration"""

import copy
import six

spacey = lambda x: (isinstance(x, six.string_types) and x.isspace()) or x == ''

class UnspacedList(list):
    """Wrap a list [of lists], making any whitespace entries magically invisible"""

    def __init__(self, list_source):
        # ensure our argument is not a generator, and duplicate any sublists
        self.spaced = copy.deepcopy(list(list_source))
        self.dirty = False

        # Turn self into a version of the source list that has spaces removed
        # and all sub-lists also UnspacedList()ed
        list.__init__(self, list_source)
        for i, entry in reversed(list(enumerate(self))):
            if isinstance(entry, list):
                sublist = UnspacedList(entry)
                list.__setitem__(self, i, sublist)
                self.spaced[i] = sublist.spaced
            elif spacey(entry):
                # don't delete comments
                if "#" not in self[:i]:
                    list.__delitem__(self, i)

    def _coerce(self, inbound):
        """
        Coerce some inbound object to be appropriately usable in this object

        :param inbound: string or None or list or UnspacedList
        :returns: (coerced UnspacedList or string or None, spaced equivalent)
        :rtype: tuple

        """
        if not isinstance(inbound, list):                      # str or None
            return (inbound, inbound)
        else:
            if not hasattr(inbound, "spaced"):
                inbound = UnspacedList(inbound)
            return (inbound, inbound.spaced)


    def insert(self, i, x):
        item, spaced_item = self._coerce(x)
        slicepos = self._spaced_position(i) if i < len(self) else len(self.spaced)
        self.spaced.insert(slicepos, spaced_item)
        if not spacey(item):
            list.insert(self, i, item)
        self.dirty = True

    def append(self, x):
        item, spaced_item = self._coerce(x)
        self.spaced.append(spaced_item)
        if not spacey(item):
            list.append(self, item)
        self.dirty = True

    def extend(self, x):
        item, spaced_item = self._coerce(x)
        self.spaced.extend(spaced_item)
        list.extend(self, item)
        self.dirty = True

    def __add__(self, other):
        l = copy.deepcopy(self)
        l.extend(other)
        l.dirty = True
        return l

    def pop(self, _i=None):
        raise NotImplementedError("UnspacedList.pop() not yet implemented")
    def remove(self, _):
        raise NotImplementedError("UnspacedList.remove() not yet implemented")
    def reverse(self):
        raise NotImplementedError("UnspacedList.reverse() not yet implemented")
    def sort(self, _cmp=None, _key=None, _Rev=None):
        raise NotImplementedError("UnspacedList.sort() not yet implemented")
    def __setslice__(self, _i, _j, _newslice):
        raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")

    def __setitem__(self, i, value):
        if isinstance(i, slice):
            raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")
        item, spaced_item = self._coerce(value)
        self.spaced.__setitem__(self._spaced_position(i), spaced_item)
        if not spacey(item):
            list.__setitem__(self, i, item)
        self.dirty = True

    def __delitem__(self, i):
        self.spaced.__delitem__(self._spaced_position(i))
        list.__delitem__(self, i)
        self.dirty = True

    def __deepcopy__(self, memo):
        new_spaced = copy.deepcopy(self.spaced, memo=memo)
        l = UnspacedList(new_spaced)
        l.dirty = self.dirty
        return l

    def is_dirty(self):
        """Recurse through the parse tree to figure out if any sublists are dirty"""
        if self.dirty:
            return True
        return any((isinstance(x, list) and x.is_dirty() for x in self))

    def _spaced_position(self, idx):
        "Convert from indexes in the unspaced list to positions in the spaced one"
        pos = spaces = 0
        # Normalize indexes like list[-1] etc, and save the result
        if idx < 0:
            idx = len(self) + idx
        if not 0 <= idx < len(self):
            raise IndexError("list index out of range")
        idx0 = idx
        # Count the number of spaces in the spaced list before idx in the unspaced one
        while idx != -1:
            if spacey(self.spaced[pos]):
                spaces += 1
            else:
                idx -= 1
            pos += 1
        return idx0 + spaces
