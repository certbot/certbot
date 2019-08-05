"""Runtime assertions for two different parser implementations"""

def simpleassert(old_value, new_value):
    """
    Simple assertion
    """
    assert old_value == new_value

def legacy_assert_list(old_list, new_list):
    """
    Used to assert that both of the lists contain the same values.
    """

    assert len(old_list) == len(new_list)
    assert all([True for ol in old_list if ol in new_list])

def legacy_assert_dir(old_result, new_result):
    """
    Used to test and ensure that the new implementation search results matches
    the old implementation results. This test is intended to be used only to test
    the old Augeas implementation results against the ParserNode Augeas implementation.

    This test expects the DirectiveNode to have Augeas path in its attribute dict
    "_metadata" with key "augpath".

    """

    if new_result != "CERTBOT_PASS_ASSERT":
        return

    assert len(old_result) == len(new_result)

    matching = []

    for oldres in old_result:
        match = [res for res in new_result if res._metadata["augpath"] == oldres]
        assert len(match) == 1


def legacy_assert_args(old_result, new_result, parser):
    """
    Used to test and ensure that returned parameter values are the same for
    the old and the new implementation.

    Uses ApacheParser to actually fetch the parameter for the old result.

    This assertion is structured this way because of how parser.get_arg() is
    currently used in the ApacheConfigurator, making it easier to test the
    results.
    """

    if isinstance(old_result, list):
        for old in old_result:
            oldarg = parser.get_arg(old_result)
            assert oldarg in new_result.parameters
    else:
        oldarg = parser.get_arg(old_result)
        assert oldarg in new_result.parameters

def assert_dir(first, second):
    """
    Used to test that DirectiveNode results match for both implementations.
    """

    if "CERTBOT_PASS_ASSERT" in [first, second]:
        return

    assert first.name == second.name
    assert first.parameters == second.parameters
    assert first.dirty == second.dirty


def assert_block(first, second):
    """
    Used to test that BlockNode results match for both implementations.
    """

    if "CERTBOT_PASS_ASSERT" in [first, second]:
        return

    assert first.name == second.name
    assert first.parameters == second.parameters
    assert len(first.children) == len(second.children)
    assert first.dirty == second.dirty
