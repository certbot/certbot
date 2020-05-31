"""
Basically a contains parser that is faster, because it tries to parse only
parts and if anything changes, it only reparses the changed parts.

It works with a simple diff in the beginning and will try to reuse old parser
fragments.
"""
import re
import difflib
from collections import namedtuple
import logging

from parso.utils import split_lines
from parso.python.parser import Parser
from parso.python.tree import EndMarker
from parso.python.tokenize import PythonToken
from parso.python.token import PythonTokenTypes

LOG = logging.getLogger(__name__)
DEBUG_DIFF_PARSER = False

_INDENTATION_TOKENS = 'INDENT', 'ERROR_DEDENT', 'DEDENT'


def _get_previous_leaf_if_indentation(leaf):
    while leaf and leaf.type == 'error_leaf' \
            and leaf.token_type in _INDENTATION_TOKENS:
        leaf = leaf.get_previous_leaf()
    return leaf


def _get_next_leaf_if_indentation(leaf):
    while leaf and leaf.type == 'error_leaf' \
            and leaf.token_type in _INDENTATION_TOKENS:
        leaf = leaf.get_previous_leaf()
    return leaf


def _assert_valid_graph(node):
    """
    Checks if the parent/children relationship is correct.

    This is a check that only runs during debugging/testing.
    """
    try:
        children = node.children
    except AttributeError:
        # Ignore INDENT is necessary, because indent/dedent tokens don't
        # contain value/prefix and are just around, because of the tokenizer.
        if node.type == 'error_leaf' and node.token_type in _INDENTATION_TOKENS:
            assert not node.value
            assert not node.prefix
            return

        # Calculate the content between two start positions.
        previous_leaf = _get_previous_leaf_if_indentation(node.get_previous_leaf())
        if previous_leaf is None:
            content = node.prefix
            previous_start_pos = 1, 0
        else:
            assert previous_leaf.end_pos <= node.start_pos, \
                (previous_leaf, node)

            content = previous_leaf.value + node.prefix
            previous_start_pos = previous_leaf.start_pos

        if '\n' in content or '\r' in content:
            splitted = split_lines(content)
            line = previous_start_pos[0] + len(splitted) - 1
            actual = line, len(splitted[-1])
        else:
            actual = previous_start_pos[0], previous_start_pos[1] + len(content)

        assert node.start_pos == actual, (node.start_pos, actual)
    else:
        for child in children:
            assert child.parent == node, (node, child)
            _assert_valid_graph(child)


def _get_debug_error_message(module, old_lines, new_lines):
    current_lines = split_lines(module.get_code(), keepends=True)
    current_diff = difflib.unified_diff(new_lines, current_lines)
    old_new_diff = difflib.unified_diff(old_lines, new_lines)
    import parso
    return (
        "There's an issue with the diff parser. Please "
        "report (parso v%s) - Old/New:\n%s\nActual Diff (May be empty):\n%s"
        % (parso.__version__, ''.join(old_new_diff), ''.join(current_diff))
    )


def _get_last_line(node_or_leaf):
    last_leaf = node_or_leaf.get_last_leaf()
    if _ends_with_newline(last_leaf):
        return last_leaf.start_pos[0]
    else:
        return last_leaf.end_pos[0]


def _skip_dedent_error_leaves(leaf):
    while leaf is not None and leaf.type == 'error_leaf' and leaf.token_type == 'DEDENT':
        leaf = leaf.get_previous_leaf()
    return leaf


def _ends_with_newline(leaf, suffix=''):
    leaf = _skip_dedent_error_leaves(leaf)

    if leaf.type == 'error_leaf':
        typ = leaf.token_type.lower()
    else:
        typ = leaf.type

    return typ == 'newline' or suffix.endswith('\n') or suffix.endswith('\r')


def _flows_finished(pgen_grammar, stack):
    """
    if, while, for and try might not be finished, because another part might
    still be parsed.
    """
    for stack_node in stack:
        if stack_node.nonterminal in ('if_stmt', 'while_stmt', 'for_stmt', 'try_stmt'):
            return False
    return True


def _func_or_class_has_suite(node):
    if node.type == 'decorated':
        node = node.children[-1]
    if node.type in ('async_funcdef', 'async_stmt'):
        node = node.children[-1]
    return node.type in ('classdef', 'funcdef') and node.children[-1].type == 'suite'


def _suite_or_file_input_is_valid(pgen_grammar, stack):
    if not _flows_finished(pgen_grammar, stack):
        return False

    for stack_node in reversed(stack):
        if stack_node.nonterminal == 'decorator':
            # A decorator is only valid with the upcoming function.
            return False

        if stack_node.nonterminal == 'suite':
            # If only newline is in the suite, the suite is not valid, yet.
            return len(stack_node.nodes) > 1
    # Not reaching a suite means that we're dealing with file_input levels
    # where there's no need for a valid statement in it. It can also be empty.
    return True


def _is_flow_node(node):
    if node.type == 'async_stmt':
        node = node.children[1]
    try:
        value = node.children[0].value
    except AttributeError:
        return False
    return value in ('if', 'for', 'while', 'try', 'with')


class _PositionUpdatingFinished(Exception):
    pass


def _update_positions(nodes, line_offset, last_leaf):
    for node in nodes:
        try:
            children = node.children
        except AttributeError:
            # Is a leaf
            node.line += line_offset
            if node is last_leaf:
                raise _PositionUpdatingFinished
        else:
            _update_positions(children, line_offset, last_leaf)


class DiffParser(object):
    """
    An advanced form of parsing a file faster. Unfortunately comes with huge
    side effects. It changes the given module.
    """
    def __init__(self, pgen_grammar, tokenizer, module):
        self._pgen_grammar = pgen_grammar
        self._tokenizer = tokenizer
        self._module = module

    def _reset(self):
        self._copy_count = 0
        self._parser_count = 0

        self._nodes_tree = _NodesTree(self._module)

    def update(self, old_lines, new_lines):
        '''
        The algorithm works as follows:

        Equal:
            - Assure that the start is a newline, otherwise parse until we get
              one.
            - Copy from parsed_until_line + 1 to max(i2 + 1)
            - Make sure that the indentation is correct (e.g. add DEDENT)
            - Add old and change positions
        Insert:
            - Parse from parsed_until_line + 1 to min(j2 + 1), hopefully not
              much more.

        Returns the new module node.
        '''
        LOG.debug('diff parser start')
        # Reset the used names cache so they get regenerated.
        self._module._used_names = None

        self._parser_lines_new = new_lines

        self._reset()

        line_length = len(new_lines)
        sm = difflib.SequenceMatcher(None, old_lines, self._parser_lines_new)
        opcodes = sm.get_opcodes()
        LOG.debug('line_lengths old: %s; new: %s' % (len(old_lines), line_length))

        for operation, i1, i2, j1, j2 in opcodes:
            LOG.debug('-> code[%s] old[%s:%s] new[%s:%s]',
                      operation, i1 + 1, i2, j1 + 1, j2)

            if j2 == line_length and new_lines[-1] == '':
                # The empty part after the last newline is not relevant.
                j2 -= 1

            if operation == 'equal':
                line_offset = j1 - i1
                self._copy_from_old_parser(line_offset, i2, j2)
            elif operation == 'replace':
                self._parse(until_line=j2)
            elif operation == 'insert':
                self._parse(until_line=j2)
            else:
                assert operation == 'delete'

        # With this action all change will finally be applied and we have a
        # changed module.
        self._nodes_tree.close()

        if DEBUG_DIFF_PARSER:
            # If there is reasonable suspicion that the diff parser is not
            # behaving well, this should be enabled.
            try:
                assert self._module.get_code() == ''.join(new_lines)
                _assert_valid_graph(self._module)
            except AssertionError:
                print(_get_debug_error_message(self._module, old_lines, new_lines))
                raise

        last_pos = self._module.end_pos[0]
        if last_pos != line_length:
            raise Exception(
                ('(%s != %s) ' % (last_pos, line_length))
                + _get_debug_error_message(self._module, old_lines, new_lines)
            )
        LOG.debug('diff parser end')
        return self._module

    def _enabled_debugging(self, old_lines, lines_new):
        if self._module.get_code() != ''.join(lines_new):
            LOG.warning('parser issue:\n%s\n%s', ''.join(old_lines), ''.join(lines_new))

    def _copy_from_old_parser(self, line_offset, until_line_old, until_line_new):
        last_until_line = -1
        while until_line_new > self._nodes_tree.parsed_until_line:
            parsed_until_line_old = self._nodes_tree.parsed_until_line - line_offset
            line_stmt = self._get_old_line_stmt(parsed_until_line_old + 1)
            if line_stmt is None:
                # Parse 1 line at least. We don't need more, because we just
                # want to get into a state where the old parser has statements
                # again that can be copied (e.g. not lines within parentheses).
                self._parse(self._nodes_tree.parsed_until_line + 1)
            else:
                p_children = line_stmt.parent.children
                index = p_children.index(line_stmt)

                from_ = self._nodes_tree.parsed_until_line + 1
                copied_nodes = self._nodes_tree.copy_nodes(
                    p_children[index:],
                    until_line_old,
                    line_offset
                )
                # Match all the nodes that are in the wanted range.
                if copied_nodes:
                    self._copy_count += 1

                    to = self._nodes_tree.parsed_until_line

                    LOG.debug('copy old[%s:%s] new[%s:%s]',
                              copied_nodes[0].start_pos[0],
                              copied_nodes[-1].end_pos[0] - 1, from_, to)
                else:
                    # We have copied as much as possible (but definitely not too
                    # much). Therefore we just parse a bit more.
                    self._parse(self._nodes_tree.parsed_until_line + 1)
            # Since there are potential bugs that might loop here endlessly, we
            # just stop here.
            assert last_until_line != self._nodes_tree.parsed_until_line, last_until_line
            last_until_line = self._nodes_tree.parsed_until_line

    def _get_old_line_stmt(self, old_line):
        leaf = self._module.get_leaf_for_position((old_line, 0), include_prefixes=True)

        if _ends_with_newline(leaf):
            leaf = leaf.get_next_leaf()
        if leaf.get_start_pos_of_prefix()[0] == old_line:
            node = leaf
            while node.parent.type not in ('file_input', 'suite'):
                node = node.parent

            # Make sure that if only the `else:` line of an if statement is
            # copied that not the whole thing is going to be copied.
            if node.start_pos[0] >= old_line:
                return node
        # Must be on the same line. Otherwise we need to parse that bit.
        return None

    def _parse(self, until_line):
        """
        Parses at least until the given line, but might just parse more until a
        valid state is reached.
        """
        last_until_line = 0
        while until_line > self._nodes_tree.parsed_until_line:
            node = self._try_parse_part(until_line)
            nodes = node.children

            self._nodes_tree.add_parsed_nodes(nodes)
            LOG.debug(
                'parse_part from %s to %s (to %s in part parser)',
                nodes[0].get_start_pos_of_prefix()[0],
                self._nodes_tree.parsed_until_line,
                node.end_pos[0] - 1
            )
            # Since the tokenizer sometimes has bugs, we cannot be sure that
            # this loop terminates. Therefore assert that there's always a
            # change.
            assert last_until_line != self._nodes_tree.parsed_until_line, last_until_line
            last_until_line = self._nodes_tree.parsed_until_line

    def _try_parse_part(self, until_line):
        """
        Sets up a normal parser that uses a spezialized tokenizer to only parse
        until a certain position (or a bit longer if the statement hasn't
        ended.
        """
        self._parser_count += 1
        # TODO speed up, shouldn't copy the whole list all the time.
        # memoryview?
        parsed_until_line = self._nodes_tree.parsed_until_line
        lines_after = self._parser_lines_new[parsed_until_line:]
        tokens = self._diff_tokenize(
            lines_after,
            until_line,
            line_offset=parsed_until_line
        )
        self._active_parser = Parser(
            self._pgen_grammar,
            error_recovery=True
        )
        return self._active_parser.parse(tokens=tokens)

    def _diff_tokenize(self, lines, until_line, line_offset=0):
        is_first_token = True
        omitted_first_indent = False
        indents = []
        tokens = self._tokenizer(lines, (1, 0))
        stack = self._active_parser.stack
        for typ, string, start_pos, prefix in tokens:
            start_pos = start_pos[0] + line_offset, start_pos[1]
            if typ == PythonTokenTypes.INDENT:
                indents.append(start_pos[1])
                if is_first_token:
                    omitted_first_indent = True
                    # We want to get rid of indents that are only here because
                    # we only parse part of the file. These indents would only
                    # get parsed as error leafs, which doesn't make any sense.
                    is_first_token = False
                    continue
            is_first_token = False

            # In case of omitted_first_indent, it might not be dedented fully.
            # However this is a sign for us that a dedent happened.
            if typ == PythonTokenTypes.DEDENT \
                    or typ == PythonTokenTypes.ERROR_DEDENT \
                    and omitted_first_indent and len(indents) == 1:
                indents.pop()
                if omitted_first_indent and not indents:
                    # We are done here, only thing that can come now is an
                    # endmarker or another dedented code block.
                    typ, string, start_pos, prefix = next(tokens)
                    if '\n' in prefix or '\r' in prefix:
                        prefix = re.sub(r'[^\n\r]+\Z', '', prefix)
                    else:
                        assert start_pos[1] >= len(prefix), repr(prefix)
                        if start_pos[1] - len(prefix) == 0:
                            prefix = ''
                    yield PythonToken(
                        PythonTokenTypes.ENDMARKER, '',
                        (start_pos[0] + line_offset, 0),
                        prefix
                    )
                    break
            elif typ == PythonTokenTypes.NEWLINE and start_pos[0] >= until_line:
                yield PythonToken(typ, string, start_pos, prefix)
                # Check if the parser is actually in a valid suite state.
                if _suite_or_file_input_is_valid(self._pgen_grammar, stack):
                    start_pos = start_pos[0] + 1, 0
                    while len(indents) > int(omitted_first_indent):
                        indents.pop()
                        yield PythonToken(PythonTokenTypes.DEDENT, '', start_pos, '')

                    yield PythonToken(PythonTokenTypes.ENDMARKER, '', start_pos, '')
                    break
                else:
                    continue

            yield PythonToken(typ, string, start_pos, prefix)


class _NodesTreeNode(object):
    _ChildrenGroup = namedtuple('_ChildrenGroup', 'prefix children line_offset last_line_offset_leaf')

    def __init__(self, tree_node, parent=None):
        self.tree_node = tree_node
        self._children_groups = []
        self.parent = parent
        self._node_children = []

    def finish(self):
        children = []
        for prefix, children_part, line_offset, last_line_offset_leaf in self._children_groups:
            first_leaf = _get_next_leaf_if_indentation(
                children_part[0].get_first_leaf()
            )

            first_leaf.prefix = prefix + first_leaf.prefix
            if line_offset != 0:
                try:
                    _update_positions(
                        children_part, line_offset, last_line_offset_leaf)
                except _PositionUpdatingFinished:
                    pass
            children += children_part
        self.tree_node.children = children
        # Reset the parents
        for node in children:
            node.parent = self.tree_node

        for node_child in self._node_children:
            node_child.finish()

    def add_child_node(self, child_node):
        self._node_children.append(child_node)

    def add_tree_nodes(self, prefix, children, line_offset=0, last_line_offset_leaf=None):
        if last_line_offset_leaf is None:
            last_line_offset_leaf = children[-1].get_last_leaf()
        group = self._ChildrenGroup(prefix, children, line_offset, last_line_offset_leaf)
        self._children_groups.append(group)

    def get_last_line(self, suffix):
        line = 0
        if self._children_groups:
            children_group = self._children_groups[-1]
            last_leaf = _get_previous_leaf_if_indentation(
                children_group.last_line_offset_leaf
            )

            line = last_leaf.end_pos[0] + children_group.line_offset

            # Newlines end on the next line, which means that they would cover
            # the next line. That line is not fully parsed at this point.
            if _ends_with_newline(last_leaf, suffix):
                line -= 1
        line += len(split_lines(suffix)) - 1

        if suffix and not suffix.endswith('\n') and not suffix.endswith('\r'):
            # This is the end of a file (that doesn't end with a newline).
            line += 1

        if self._node_children:
            return max(line, self._node_children[-1].get_last_line(suffix))
        return line


class _NodesTree(object):
    def __init__(self, module):
        self._base_node = _NodesTreeNode(module)
        self._working_stack = [self._base_node]
        self._module = module
        self._prefix_remainder = ''
        self.prefix = ''

    @property
    def parsed_until_line(self):
        return self._working_stack[-1].get_last_line(self.prefix)

    def _get_insertion_node(self, indentation_node):
        indentation = indentation_node.start_pos[1]

        # find insertion node
        while True:
            node = self._working_stack[-1]
            tree_node = node.tree_node
            if tree_node.type == 'suite':
                # A suite starts with NEWLINE, ...
                node_indentation = tree_node.children[1].start_pos[1]

                if indentation >= node_indentation:  # Not a Dedent
                    # We might be at the most outer layer: modules. We
                    # don't want to depend on the first statement
                    # having the right indentation.
                    return node

            elif tree_node.type == 'file_input':
                return node

            self._working_stack.pop()

    def add_parsed_nodes(self, tree_nodes):
        old_prefix = self.prefix
        tree_nodes = self._remove_endmarker(tree_nodes)
        if not tree_nodes:
            self.prefix = old_prefix + self.prefix
            return

        assert tree_nodes[0].type != 'newline'

        node = self._get_insertion_node(tree_nodes[0])
        assert node.tree_node.type in ('suite', 'file_input')
        node.add_tree_nodes(old_prefix, tree_nodes)
        # tos = Top of stack
        self._update_tos(tree_nodes[-1])

    def _update_tos(self, tree_node):
        if tree_node.type in ('suite', 'file_input'):
            new_tos = _NodesTreeNode(tree_node)
            new_tos.add_tree_nodes('', list(tree_node.children))

            self._working_stack[-1].add_child_node(new_tos)
            self._working_stack.append(new_tos)

            self._update_tos(tree_node.children[-1])
        elif _func_or_class_has_suite(tree_node):
            self._update_tos(tree_node.children[-1])

    def _remove_endmarker(self, tree_nodes):
        """
        Helps cleaning up the tree nodes that get inserted.
        """
        last_leaf = tree_nodes[-1].get_last_leaf()
        is_endmarker = last_leaf.type == 'endmarker'
        self._prefix_remainder = ''
        if is_endmarker:
            separation = max(last_leaf.prefix.rfind('\n'), last_leaf.prefix.rfind('\r'))
            if separation > -1:
                # Remove the whitespace part of the prefix after a newline.
                # That is not relevant if parentheses were opened. Always parse
                # until the end of a line.
                last_leaf.prefix, self._prefix_remainder = \
                    last_leaf.prefix[:separation + 1], last_leaf.prefix[separation + 1:]

        self.prefix = ''

        if is_endmarker:
            self.prefix = last_leaf.prefix

            tree_nodes = tree_nodes[:-1]
        return tree_nodes

    def copy_nodes(self, tree_nodes, until_line, line_offset):
        """
        Copies tree nodes from the old parser tree.

        Returns the number of tree nodes that were copied.
        """
        if tree_nodes[0].type in ('error_leaf', 'error_node'):
            # Avoid copying errors in the beginning. Can lead to a lot of
            # issues.
            return []

        self._get_insertion_node(tree_nodes[0])

        new_nodes, self._working_stack, self.prefix = self._copy_nodes(
            list(self._working_stack),
            tree_nodes,
            until_line,
            line_offset,
            self.prefix,
        )
        return new_nodes

    def _copy_nodes(self, working_stack, nodes, until_line, line_offset, prefix=''):
        new_nodes = []

        new_prefix = ''
        for node in nodes:
            if node.start_pos[0] > until_line:
                break

            if node.type == 'endmarker':
                break

            if node.type == 'error_leaf' and node.token_type in ('DEDENT', 'ERROR_DEDENT'):
                break
            # TODO this check might take a bit of time for large files. We
            # might want to change this to do more intelligent guessing or
            # binary search.
            if _get_last_line(node) > until_line:
                # We can split up functions and classes later.
                if _func_or_class_has_suite(node):
                    new_nodes.append(node)
                break

            new_nodes.append(node)

        if not new_nodes:
            return [], working_stack, prefix

        tos = working_stack[-1]
        last_node = new_nodes[-1]
        had_valid_suite_last = False
        if _func_or_class_has_suite(last_node):
            suite = last_node
            while suite.type != 'suite':
                suite = suite.children[-1]

            suite_tos = _NodesTreeNode(suite)
            # Don't need to pass line_offset here, it's already done by the
            # parent.
            suite_nodes, new_working_stack, new_prefix = self._copy_nodes(
                working_stack + [suite_tos], suite.children, until_line, line_offset
            )
            if len(suite_nodes) < 2:
                # A suite only with newline is not valid.
                new_nodes.pop()
                new_prefix = ''
            else:
                assert new_nodes
                tos.add_child_node(suite_tos)
                working_stack = new_working_stack
                had_valid_suite_last = True

        if new_nodes:
            last_node = new_nodes[-1]
            if (last_node.type in ('error_leaf', 'error_node') or
                    _is_flow_node(new_nodes[-1])):
                # Error leafs/nodes don't have a defined start/end. Error
                # nodes might not end with a newline (e.g. if there's an
                # open `(`). Therefore ignore all of them unless they are
                # succeeded with valid parser state.
                # If we copy flows at the end, they might be continued
                # after the copy limit (in the new parser).
                # In this while loop we try to remove until we find a newline.
                new_prefix = ''
                new_nodes.pop()
                while new_nodes:
                    last_node = new_nodes[-1]
                    if last_node.get_last_leaf().type == 'newline':
                        break
                    new_nodes.pop()

        if new_nodes:
            if not _ends_with_newline(new_nodes[-1].get_last_leaf()) and not had_valid_suite_last:
                p = new_nodes[-1].get_next_leaf().prefix
                # We are not allowed to remove the newline at the end of the
                # line, otherwise it's going to be missing. This happens e.g.
                # if a bracket is around before that moves newlines to
                # prefixes.
                new_prefix = split_lines(p, keepends=True)[0]

            if had_valid_suite_last:
                last = new_nodes[-1]
                if last.type == 'decorated':
                    last = last.children[-1]
                if last.type in ('async_funcdef', 'async_stmt'):
                    last = last.children[-1]
                last_line_offset_leaf = last.children[-2].get_last_leaf()
                assert last_line_offset_leaf == ':'
            else:
                last_line_offset_leaf = new_nodes[-1].get_last_leaf()
            tos.add_tree_nodes(prefix, new_nodes, line_offset, last_line_offset_leaf)
            prefix = new_prefix
            self._prefix_remainder = ''

        return new_nodes, working_stack, prefix

    def close(self):
        self._base_node.finish()

        # Add an endmarker.
        try:
            last_leaf = self._module.get_last_leaf()
        except IndexError:
            end_pos = [1, 0]
        else:
            last_leaf = _skip_dedent_error_leaves(last_leaf)
            end_pos = list(last_leaf.end_pos)
        lines = split_lines(self.prefix)
        assert len(lines) > 0
        if len(lines) == 1:
            end_pos[1] += len(lines[0])
        else:
            end_pos[0] += len(lines) - 1
            end_pos[1] = len(lines[-1])

        endmarker = EndMarker('', tuple(end_pos), self.prefix + self._prefix_remainder)
        endmarker.parent = self._module
        self._module.children.append(endmarker)
