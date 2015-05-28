"""Send e-mail notification to system administrators."""

import email
import smtplib
import socket
import subprocess


def notify(subject, whom, what):
    """Send email notification.

    Try to notify the addressee (``whom``) by e-mail, with Subject:
    defined by ``subject`` and message body by ``what``.

    """
    msg = email.message_from_string(what)
    msg.add_header("From", "Let's Encrypt renewal agent <root>")
    msg.add_header("To", whom)
    msg.add_header("Subject", subject)
    msg = msg.as_string()
    try:
        lmtp = smtplib.LMTP()
        lmtp.connect()
        lmtp.sendmail("root", [whom], msg)
    except (smtplib.SMTPHeloError, smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused, smtplib.SMTPDataError, socket.error):
        # We should try using /usr/sbin/sendmail in this case
        try:
            proc = subprocess.Popen(["/usr/sbin/sendmail", "-t"],
                                    stdin=subprocess.PIPE)
            proc.communicate(msg)
        except OSError:
            return False
    return True
