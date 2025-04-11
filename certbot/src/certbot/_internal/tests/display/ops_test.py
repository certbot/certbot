# coding=utf-8
"""Test certbot.display.ops."""
import sys
import unittest
from unittest import mock

import josepy as jose
import pytest

from acme import messages
from certbot import errors
from certbot._internal import account
from certbot._internal.display import obj as display_obj
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import ops
from certbot.display import util as display_util
import certbot.tests.util as test_util

KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class GetEmailTest(unittest.TestCase):
    """Tests for certbot.display.ops.get_email."""

    @classmethod
    def _call(cls, **kwargs):
        from certbot.display.ops import get_email
        return get_email(**kwargs)

    @test_util.patch_display_util()
    def test_cancel_none(self, mock_get_utility):
        mock_input = mock_get_utility().input
        mock_input.return_value = (display_util.CANCEL, "foo@bar.baz")
        with pytest.raises(errors.Error):
            self._call()
        with pytest.raises(errors.Error):
            self._call()

    @test_util.patch_display_util()
    def test_ok_safe(self, mock_get_utility):
        mock_input = mock_get_utility().input
        mock_input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.util.safe_email") as mock_safe_email:
            mock_safe_email.return_value = True
            assert self._call() == "foo@bar.baz"

    @test_util.patch_display_util()
    def test_ok_not_safe(self, mock_get_utility):
        mock_input = mock_get_utility().input
        mock_input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.util.safe_email") as mock_safe_email:
            mock_safe_email.side_effect = [False, True]
            assert self._call() == "foo@bar.baz"

    @test_util.patch_display_util()
    def test_invalid_flag(self, mock_get_utility):
        invalid_txt = "The server reported a problem"
        mock_input = mock_get_utility().input
        mock_input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.util.safe_email") as mock_safe_email:
            mock_safe_email.return_value = True
            self._call()
            assert invalid_txt not in mock_input.call_args[0][0]
            self._call(invalid=True)
            assert invalid_txt in mock_input.call_args[0][0]

    @test_util.patch_display_util()
    def test_optional_invalid_unsafe(self, mock_get_utility):
        invalid_txt = "There is a problem"
        mock_input = mock_get_utility().input
        mock_input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.util.safe_email") as mock_safe_email:
            mock_safe_email.side_effect = [False, True]
            self._call(invalid=True)
            assert invalid_txt in mock_input.call_args[0][0]


class ChooseAccountTest(test_util.TempDirTestCase):
    """Tests for certbot.display.ops.choose_account."""
    def setUp(self):
        super().setUp()

        display_obj.set_display(display_obj.FileDisplay(sys.stdout, False))

        self.account_keys_dir = os.path.join(self.tempdir, "keys")
        filesystem.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            accounts_dir=self.tempdir,
            account_keys_dir=self.account_keys_dir,
            server="certbot-demo.org")
        self.key = KEY

        self.acc1 = account.Account(messages.RegistrationResource(
            uri=None, body=messages.Registration.from_data(
                email="email1@g.com")), self.key)
        self.acc2 = account.Account(messages.RegistrationResource(
            uri=None, body=messages.Registration.from_data(
                email="email2@g.com", phone="phone")), self.key)

    @classmethod
    def _call(cls, accounts):
        return ops.choose_account(accounts)

    @test_util.patch_display_util()
    def test_one(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        assert self._call([self.acc1]) == self.acc1

    @test_util.patch_display_util()
    def test_two(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        assert self._call([self.acc1, self.acc2]) == self.acc2

    @test_util.patch_display_util()
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 1)
        assert self._call([self.acc1, self.acc2]) is None


class GenHttpsNamesTest(unittest.TestCase):
    """Test _gen_https_names."""
    def setUp(self):
        display_obj.set_display(display_obj.FileDisplay(sys.stdout, False))

    @classmethod
    def _call(cls, domains):
        from certbot.display.ops import _gen_https_names
        return _gen_https_names(domains)

    def test_zero(self):
        assert self._call([]) == ""

    def test_one(self):
        doms = [
            "example.com",
            "asllkjsadfljasdf.c",
        ]
        for dom in doms:
            assert self._call([dom]) == "https://%s" % dom

    def test_two(self):
        domains_list = [
            ["foo.bar.org", "bar.org"],
            ["paypal.google.facebook.live.com", "*.zombo.example.com"],
        ]
        for doms in domains_list:
            assert self._call(doms) == \
                "https://{dom[0]} and https://{dom[1]}".format(dom=doms)

    def test_three(self):
        doms = ["a.org", "b.org", "c.org"]
        # We use an oxford comma
        assert self._call(doms) == \
            "https://{dom[0]}, https://{dom[1]}, and https://{dom[2]}".format(
                dom=doms)

    def test_four(self):
        doms = ["a.org", "b.org", "c.org", "d.org"]
        exp = ("https://{dom[0]}, https://{dom[1]}, https://{dom[2]}, "
               "and https://{dom[3]}".format(dom=doms))

        assert self._call(doms) == exp


class ChooseNamesTest(unittest.TestCase):
    """Test choose names."""
    def setUp(self):
        display_obj.set_display(display_obj.FileDisplay(sys.stdout, False))
        self.mock_install = mock.MagicMock()

    @classmethod
    def _call(cls, installer, question=None):
        from certbot.display.ops import choose_names
        return choose_names(installer, question)

    @mock.patch("certbot.display.ops._choose_names_manually")
    def test_no_installer(self, mock_manual):
        self._call(None)
        assert mock_manual.call_count == 1

    @test_util.patch_display_util()
    def test_no_installer_cancel(self, mock_util):
        mock_util().input.return_value = (display_util.CANCEL, [])
        assert self._call(None) == []

    @test_util.patch_display_util()
    def test_no_names_choose(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        domain = "example.com"
        mock_util().input.return_value = (display_util.OK, domain)

        actual_doms = self._call(self.mock_install)
        assert mock_util().input.call_count == 1
        assert actual_doms == [domain]

    def test_sort_names_trivial(self):
        from certbot.display.ops import _sort_names

        #sort an empty list
        assert _sort_names([]) == []

        #sort simple domains
        some_domains = ["ex.com", "zx.com", "ax.com"]
        assert _sort_names(some_domains) == ["ax.com", "ex.com", "zx.com"]

        #Sort subdomains of a single domain
        domain = ".ex.com"
        unsorted_short = ["e", "a", "z", "y"]
        unsorted_long = [us + domain for us in unsorted_short]

        sorted_short = sorted(unsorted_short)
        sorted_long = [us + domain for us in sorted_short]

        assert _sort_names(unsorted_long) == sorted_long

    def test_sort_names_many(self):
        from certbot.display.ops import _sort_names

        unsorted_domains = [".cx.com", ".bx.com", ".ax.com", ".dx.com"]
        unsorted_short = ["www", "bnother.long.subdomain", "a", "a.long.subdomain", "z", "b"]
        #Of course sorted doesn't work here ;-)
        sorted_short = ["a", "b", "a.long.subdomain", "bnother.long.subdomain", "www", "z"]

        to_sort = []
        for short in unsorted_short:
            for domain in unsorted_domains:
                to_sort.append(short+domain)
        sortd = []
        for domain in sorted(unsorted_domains):
            for short in sorted_short:
                sortd.append(short+domain)
        assert _sort_names(to_sort) == sortd


    @test_util.patch_display_util()
    def test_filter_names_valid_return(self, mock_util):
        self.mock_install.get_all_names.return_value = {"example.com"}
        mock_util().checklist.return_value = (display_util.OK, ["example.com"])

        names = self._call(self.mock_install)
        assert names == ["example.com"]
        assert mock_util().checklist.call_count == 1

    @test_util.patch_display_util()
    def test_filter_namees_override_question(self, mock_util):
        self.mock_install.get_all_names.return_value = {"example.com"}
        mock_util().checklist.return_value = (display_util.OK, ["example.com"])
        names = self._call(self.mock_install, "Custom")
        assert names == ["example.com"]
        assert mock_util().checklist.call_count == 1
        assert mock_util().checklist.call_args[0][0] == "Custom"

    @test_util.patch_display_util()
    def test_filter_names_nothing_selected(self, mock_util):
        self.mock_install.get_all_names.return_value = {"example.com"}
        mock_util().checklist.return_value = (display_util.OK, [])

        assert self._call(self.mock_install) == []

    @test_util.patch_display_util()
    def test_filter_names_cancel(self, mock_util):
        self.mock_install.get_all_names.return_value = {"example.com"}
        mock_util().checklist.return_value = (
            display_util.CANCEL, ["example.com"])

        assert self._call(self.mock_install) == []

    def test_get_valid_domains(self):
        from certbot.display.ops import get_valid_domains
        all_valid = ["example.com", "second.example.com",
                     "also.example.com", "under_score.example.com",
                     "justtld", "*.wildcard.com"]
        all_invalid = ["öóòps.net", "uniçodé.com"]
        two_valid = ["example.com", "úniçøde.com", "also.example.com"]
        assert get_valid_domains(all_valid) == all_valid
        assert get_valid_domains(all_invalid) == []
        assert len(get_valid_domains(two_valid)) == 2

    @test_util.patch_display_util()
    def test_choose_manually(self, mock_util):
        from certbot.display.ops import _choose_names_manually
        utility_mock = mock_util()
        # No retry
        utility_mock.yesno.return_value = False
        # IDN and no retry
        utility_mock.input.return_value = (display_util.OK,
                                          "uniçodé.com")
        assert _choose_names_manually() == []
        # IDN exception with previous mocks
        with mock.patch(
                "certbot.display.ops.internal_display_util.separate_list_input"
        ) as mock_sli:
            unicode_error = UnicodeEncodeError('mock', u'', 0, 1, 'mock')
            mock_sli.side_effect = unicode_error
            assert _choose_names_manually() == []
        # Valid domains
        utility_mock.input.return_value = (display_util.OK,
                                          ("example.com,"
                                           "under_score.example.com,"
                                           "justtld,"
                                           "valid.example.com"))
        assert _choose_names_manually() == \
                         ["example.com", "under_score.example.com",
                          "justtld", "valid.example.com"]

    @test_util.patch_display_util()
    def test_choose_manually_retry(self, mock_util):
        from certbot.display.ops import _choose_names_manually
        utility_mock = mock_util()
        # Three iterations
        utility_mock.input.return_value = (display_util.OK,
                                          "uniçodé.com")
        utility_mock.yesno.side_effect = [True, True, False]
        _choose_names_manually()
        assert utility_mock.yesno.call_count == 3


class SuccessInstallationTest(unittest.TestCase):
    """Test the success installation message."""
    @classmethod
    def _call(cls, names):
        from certbot.display.ops import success_installation
        success_installation(names)

    @test_util.patch_display_util()
    @mock.patch("certbot.display.util.notify")
    def test_success_installation(self, mock_notify, mock_display):
        mock_display().notification.return_value = None
        names = ["example.com", "abc.com"]

        self._call(names)

        assert mock_notify.call_count == 1
        arg = mock_notify.call_args_list[0][0][0]

        for name in names:
            assert name in arg


class SuccessRenewalTest(unittest.TestCase):
    """Test the success renewal message."""
    @classmethod
    def _call(cls, names):
        from certbot.display.ops import success_renewal
        success_renewal(names)

    @test_util.patch_display_util()
    @mock.patch("certbot.display.util.notify")
    def test_success_renewal(self, mock_notify, mock_display):
        mock_display().notification.return_value = None
        names = ["example.com", "abc.com"]

        self._call(names)

        assert mock_notify.call_count == 1


class SuccessRevocationTest(unittest.TestCase):
    """Test the success revocation message."""
    @classmethod
    def _call(cls, path):
        from certbot.display.ops import success_revocation
        success_revocation(path)

    @test_util.patch_display_util()
    @mock.patch("certbot.display.util.notify")
    def test_success_revocation(self, mock_notify, unused_mock_display):
        path = "/path/to/cert.pem"
        self._call(path)
        mock_notify.assert_called_once_with(
            "Congratulations! You have successfully revoked the certificate "
            "that was located at {0}.".format(path)
        )


class ValidatorTests(unittest.TestCase):
    """Tests for `validated_input` and `validated_directory`."""

    __ERROR = "Must be non-empty"

    valid_input = "asdf"
    valid_directory = "/var/www/html"

    @staticmethod
    def __validator(m):
        if m == "":
            raise errors.PluginError(ValidatorTests.__ERROR)

    @test_util.patch_display_util()
    def test_input_blank_with_validator(self, mock_util):
        mock_util().input.side_effect = [(display_util.OK, ""),
                                         (display_util.OK, ""),
                                         (display_util.OK, ""),
                                         (display_util.OK, self.valid_input)]

        returned = ops.validated_input(self.__validator, "message", force_interactive=True)
        assert ValidatorTests.__ERROR == mock_util().notification.call_args[0][0]
        assert returned == (display_util.OK, self.valid_input)

    @test_util.patch_display_util()
    def test_input_validation_with_default(self, mock_util):
        mock_util().input.side_effect = [(display_util.OK, self.valid_input)]

        returned = ops.validated_input(self.__validator, "msg", default="other")
        assert returned == (display_util.OK, self.valid_input)

    @test_util.patch_display_util()
    def test_input_validation_with_bad_default(self, mock_util):
        mock_util().input.side_effect = [(display_util.OK, self.valid_input)]

        with pytest.raises(AssertionError):
            ops.validated_input(self.__validator, "msg", default="")

    @test_util.patch_display_util()
    def test_input_cancel_with_validator(self, mock_util):
        mock_util().input.side_effect = [(display_util.CANCEL, "")]

        code, unused_raw = ops.validated_input(self.__validator, "message", force_interactive=True)
        assert code == display_util.CANCEL

    @test_util.patch_display_util()
    def test_directory_select_validation(self, mock_util):
        mock_util().directory_select.side_effect = [(display_util.OK, ""),
                                                    (display_util.OK, self.valid_directory)]

        returned = ops.validated_directory(self.__validator, "msg", force_interactive=True)
        assert ValidatorTests.__ERROR == mock_util().notification.call_args[0][0]
        assert returned == (display_util.OK, self.valid_directory)

    @test_util.patch_display_util()
    def test_directory_select_validation_with_default(self, mock_util):
        mock_util().directory_select.side_effect = [(display_util.OK, self.valid_directory)]

        returned = ops.validated_directory(self.__validator, "msg", default="other")
        assert returned == (display_util.OK, self.valid_directory)

    @test_util.patch_display_util()
    def test_directory_select_validation_with_bad_default(self, mock_util):
        mock_util().directory_select.side_effect = [(display_util.OK, self.valid_directory)]

        with pytest.raises(AssertionError):
            ops.validated_directory(self.__validator, "msg", default="")


class ChooseValuesTest(unittest.TestCase):
    """Test choose_values."""
    @classmethod
    def _call(cls, values, question):
        from certbot.display.ops import choose_values
        return choose_values(values, question)

    @test_util.patch_display_util()
    def test_choose_names_success(self, mock_util):
        items = ["first", "second", "third"]
        mock_util().checklist.return_value = (display_util.OK, [items[2]])
        result = self._call(items, None)
        assert result == [items[2]]
        assert mock_util().checklist.called is True
        assert mock_util().checklist.call_args[0][0] == ""

    @test_util.patch_display_util()
    def test_choose_names_success_question(self, mock_util):
        items = ["first", "second", "third"]
        question = "Which one?"
        mock_util().checklist.return_value = (display_util.OK, [items[1]])
        result = self._call(items, question)
        assert result == [items[1]]
        assert mock_util().checklist.called is True
        assert mock_util().checklist.call_args[0][0] == question

    @test_util.patch_display_util()
    def test_choose_names_user_cancel(self, mock_util):
        items = ["first", "second", "third"]
        question = "Want to cancel?"
        mock_util().checklist.return_value = (display_util.CANCEL, [])
        result = self._call(items, question)
        assert result == []
        assert mock_util().checklist.called is True
        assert mock_util().checklist.call_args[0][0] == question


@mock.patch('certbot.display.ops.logger')
@mock.patch('certbot.display.util.notify')
class ReportExecutedCommand(unittest.TestCase):
    """Test report_executed_command"""
    @classmethod
    def _call(cls, cmd_name: str, rc: int, out: str, err: str):
        from certbot.display.ops import report_executed_command
        report_executed_command(cmd_name, rc, out, err)

    def test_mixed_success(self, mock_notify, mock_logger):
        self._call("some-hook", 0, "Did a thing", "Some warning")
        assert mock_logger.warning.call_count == 1
        assert mock_notify.call_count == 1

    def test_mixed_error(self, mock_notify, mock_logger):
        self._call("some-hook", -127, "Did a thing", "Some warning")
        assert mock_logger.warning.call_count == 2
        assert mock_notify.call_count == 1

    def test_empty_success(self, mock_notify, mock_logger):
        self._call("some-hook", 0, "\n", " ")
        assert mock_logger.warning.call_count == 0
        assert mock_notify.call_count == 0

if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
