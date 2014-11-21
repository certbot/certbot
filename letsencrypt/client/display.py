import textwrap

import dialog


WIDTH = 72
HEIGHT = 20


class SingletonD(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SingletonD, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance


class Display(SingletonD):
    """Generic display."""

    def generic_notification(self, message, width=WIDTH, height=HEIGHT):
        raise NotImplementedError()

    def generic_menu(self, message, choices, input_text="",
                     width=WIDTH, height=HEIGHT):
        raise NotImplementedError()

    def generic_input(self, message):
        raise NotImplementedError()

    def generic_yesno(self, message, yes_label="Yes", no_label="No"):
        raise NotImplementedError()

    def filter_names(self, names):
        raise NotImplementedError()

    def success_installation(self, domains):
        raise NotImplementedError()

    def display_certs(self, certs):
        raise NotImplementedError()

    def confirm_revocation(self, cert):
        raise NotImplementedError()

    def more_info_cert(self, cert):
        raise NotImplementedError()

    def gen_https_names(self, domains):
        """Returns a string of the https domains.

        Domains are formatted nicely with https:// prepended to each.
        """
        result = ""
        if len(domains) > 2:
            for i in range(len(domains)-1):
                result = result + "https://" + domains[i] + ", "
            result = result + "and "
        if len(domains) == 2:
            return "https://" + domains[0] + " and https://" + domains[1]
        if domains:
            result = result + "https://" + domains[len(domains)-1]

        return result

    def cert_info_frame(self, cert):
        text = "-" * (WIDTH - 4) + "\n"
        text += self.cert_info_string(cert)
        text += "-" * (WIDTH - 4)
        return text

    def cert_info_string(self, cert):
        text = "Subject: %s\n" % cert["subject"]
        text += "SAN: %s\n" % cert["san"]
        text += "Issuer: %s\n" % cert["issuer"]
        text += "Public Key: %s\n" % cert["pub_key"]
        text += "Not Before: %s\n" % str(cert["not_before"])
        text += "Not After: %s\n" % str(cert["not_after"])
        text += "Serial Number: %s\n" % cert["serial"]
        text += "SHA1: %s\n" % cert["fingerprint"]
        text += "Installed: %s\n" % cert["installed"]
        return text


class NcursesDisplay(Display):

    def __init__(self):
        self.d = dialog.Dialog()

    def generic_notification(self, message, w=WIDTH, h=HEIGHT):
        self.d.msgbox(message, width=w, height=h)

    def generic_menu(self, message, choices, input_text="", width=WIDTH,
                     height=HEIGHT):
        # Can accept either tuples or just the actual choices
        if choices and isinstance(choices[0], tuple):
            c, selection = self.d.menu(
                message, choices=choices, width=WIDTH, height=HEIGHT)
            return c, str(selection)
        else:
            choices = list(enumerate(choices, 1))
            code, s = self.d.menu(
                message, choices=choices, width=WIDTH, height=HEIGHT)

            return code(int(s) - 1)

    def generic_input(self, message):
        return self.d.inputbox(message)

    def generic_yesno(self, message, yes="Yes", no="No"):
        a = self.d.yesno(message, HEIGHT, WIDTH, yes_label=yes, no_label=no)

        return a == self.d.DIALOG_OK

    def filter_names(self, names):
        choices = [(n, "", 0) for n in names]
        c, names = self.d.checklist("Which names would you like to activate \
        HTTPS for?", choices=choices)

        return c, [str(s) for s in names]

    def success_installation(self, domains):
        self.d.msgbox("\nCongratulations! You have successfully enabled "
                      + self.gen_https_names(domains) + "!", width=WIDTH)

    def display_certs(self, certs):
        list_choices = [
            (str(i+1), "%s | %s | %s" %
                (str(c["cn"].ljust(WIDTH - 39)),
                 c["not_before"].strftime("%m-%d-%y"),
                 "Installed" if c["installed"] else ""))
            for i, c in enumerate(certs)]

        code, s = self.d.menu(
            "Which certificates would you like to revoke?",
            choices=list_choices, help_button=True,
            help_label="More Info", ok_label="Revoke",
            width=WIDTH, height=HEIGHT)
        if not s:
            s = -1
        return code, (int(s) - 1)

    def confirm_revocation(self, cert):
        text = "Are you sure you would like to revoke the following \
        certificate:\n"
        text += self.cert_info_frame(cert)
        text += "This action cannot be reversed!"
        a = self.d.yesno(text, width=WIDTH, height=HEIGHT)
        return a == self.d.DIALOG_OK

    def more_info_cert(self, cert):
        text = "Certificate Information:\n"
        text += self.cert_info_frame(cert)
        print text
        self.d.msgbox(text, width=WIDTH, height=HEIGHT)


class FileDisplay(Display):

    def __init__(self, outfile):
        self.outfile = outfile

    def generic_notification(self, message, width=WIDTH, height=HEIGHT):
        side_frame = '-' * (79)
        wm = textwrap.fill(message, 80)
        text = "\n%s\n%s\n%s\n" % (side_frame, wm, side_frame)
        self.outfile.write(text)
        raw_input("Press Enter to Continue")

    def generic_menu(self, message, choices, input_text="",
                     width=WIDTH, height=HEIGHT):
        # Can take either tuples or single items in choices list
        if choices and isinstance(choices[0], tuple):
            choices = ["%s - %s" % (c[0], c[1]) for c in choices]

        self.outfile.write("\n%s\n" % message)
        side_frame = '-' * (79)
        self.outfile.write("%s\n" % side_frame)

        for i, c in enumerate(choices):
            wc = textwrap.fill("%d: %s" % (i + 1, c), 80)
            self.outfile.write("%s\n" % wc)

        self.outfile.write("%s\n" % side_frame)

        code, selection = self.__get_valid_int_ans(
            "%s (c to cancel): " % input_text)

        return code, (selection - 1)

    def generic_input(self, message):
        ans = raw_input("%s (Enter c to cancel)\n" % message)

        if ans.startswith('c') or ans.startswith('C'):
            return CANCEL, -1
        else:
            return OK, ans

    def generic_yesno(self, message, yes_label="Yes", no_label="No"):
        self.outfile.write("\n%s\n" % textwrap.fill(message, 80))
        ans = raw_input("y/n: ")
        return ans.startswith('y') or ans.startswith('Y')

    def filter_names(self, names):
        c, s = self.generic_menu(
            "Choose the names would you like to upgrade to HTTPS?",
            names,
            "Select the number of the name: ")

        # Make sure to return a list...
        return c, [names[s]]

    def display_certs(self, certs):
        menu_choices = [(str(i+1), str(c["cn"]) + " - " + c["pub_key"] +
                         " - " + str(c["not_before"])[:-6])
                        for i, c in enumerate(certs)]

        self.outfile.write("Which certificate would you like to revoke?\n")
        for c in menu_choices:
            wm = textwrap.fill("%s: %s - %s Signed (UTC): %s\n" %
                               (c[0], c[1], c[2], c[3]))
            self.outfile.write(wm)

        return (self.__get_valid_int_ans("Revoke Number (c to cancel): ") - 1)

    def __get_valid_int_ans(self, input_string):
        valid_ans = False

        e_msg = "Please input a number or the letter c to cancel\n"
        while not valid_ans:

            ans = raw_input(input_string)
            if ans.startswith('c') or ans.startswith('C'):
                code = CANCEL
                selection = -1
                valid_ans = True
            else:
                try:
                    selection = int(ans)
                    # TODO add check to make sure it is liess than max
                    if selection < 0:
                        self.outfile.write(e_msg)
                        continue
                    code = OK
                    valid_ans = True
                except ValueError:
                    self.outfile.write(e_msg)

        return code, selection

    def success_installation(self, domains):
        s_f = '*' * (79)
        wm = textwrap.fill(("Congratulations! You have successfully " +
                           "enabled %s!") % self.gen_https_names(domains))
        msg = "%s\n%s\n%s\n"
        self.outfile.write(msg % (s_f, wm, s_f))

    def confirm_revocation(self, cert):
        self.outfile.write("Are you sure you would like to revoke \
        the following certificate:\n")
        self.outfile.write(self.cert_info_frame(cert))
        self.outfile("This action cannot be reversed!\n")
        ans = raw_input("y/n")
        return ans.startswith('y') or ans.startswith('Y')

    def more_info_cert(self, cert):
        self.outfile.write("\nCertificate Information:\n")
        self.outfile.write(self.cert_info_frame(cert))

display = None
OK = "ok"
CANCEL = "cancel"
HELP = "help"


def set_display(display_inst):
    global display
    display = display_inst


def generic_notification(message, width=WIDTH, height=HEIGHT):
    display.generic_notification(message, width, height)


def generic_menu(message, choices, input_text="", width=WIDTH, height=HEIGHT):
    return display.generic_menu(message, choices, input_text, width, height)


def generic_input(message):
    return display.generic_message(message)


def generic_yesno(message, yes_label="Yes", no_label="No"):
    return display.generic_yesno(message, yes_label, no_label)


def filter_names(names):
    return display.filter_names(names)


def display_certs(certs):
    return display.display_certs(certs)


def cert_info_string(cert):
    return display.cert_info_string(cert)


def gen_https_names(domains):
    return display.gen_https_names(domains)


def success_installation(domains):
    return display.success_installation(domains)


def redirect_by_default():
    choices = [
        ("Easy", "Allow both HTTP and HTTPS access to these sites"),
        ("Secure", "Make all requests redirect to secure HTTPS access")]

    result = display.generic_menu("Please choose whether HTTPS access " +
                                  "is required or optional.",
                                  choices,
                                  "Please enter the appropriate number",
                                  width=WIDTH)

    if result[0] != OK:
        return False

    # different answer for each type of display
    return (str(result[1]) == "Secure" or result[1] == 1)


def confirm_revocation(cert):
    return display.confirm_revocation(cert)


def more_info_cert(cert):
    return display.more_info_cert(cert)
