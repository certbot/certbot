"""Test :mod:`certbot.display.util`."""
import sys

import pytest

import certbot.tests.util as test_util


@test_util.patch_display_util()
def test_notify(mock_util):
    from certbot.display.util import notify
    notify("Hello World")
    mock_util().notification.assert_called_with(
        "Hello World", pause=False, decorate=False, wrap=False
    )


@test_util.patch_display_util()
def test_notification(mock_util):
    from certbot.display.util import notification
    notification("Hello World")
    mock_util().notification.assert_called_with(
        "Hello World", pause=True, decorate=True, wrap=True, force_interactive=False
    )


@test_util.patch_display_util()
def test_menu(mock_util):
    from certbot.display.util import menu
    menu("Hello World", ["one", "two"], default=0)
    mock_util().menu.assert_called_with(
        "Hello World", ["one", "two"], default=0, cli_flag=None, force_interactive=False
    )


@test_util.patch_display_util()
def test_input_text(mock_util):
    from certbot.display.util import input_text
    input_text("Hello World", default="something")
    mock_util().input.assert_called_with(
        "Hello World", default='something', cli_flag=None, force_interactive=False
    )


@test_util.patch_display_util()
def test_yesno(mock_util):
    from certbot.display.util import yesno
    yesno("Hello World", default=True)
    mock_util().yesno.assert_called_with(
        "Hello World", yes_label='Yes', no_label='No', default=True, cli_flag=None,
        force_interactive=False
    )


@test_util.patch_display_util()
def test_checklist(mock_util):
    from certbot.display.util import checklist
    checklist("Hello World", ["one", "two"], default="one")
    mock_util().checklist.assert_called_with(
        "Hello World", ['one', 'two'], default='one', cli_flag=None, force_interactive=False
    )


@test_util.patch_display_util()
def test_directory_select(mock_util):
    from certbot.display.util import directory_select
    directory_select("Hello World", default="something")
    mock_util().directory_select.assert_called_with(
        "Hello World", default='something', cli_flag=None, force_interactive=False
    )


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
