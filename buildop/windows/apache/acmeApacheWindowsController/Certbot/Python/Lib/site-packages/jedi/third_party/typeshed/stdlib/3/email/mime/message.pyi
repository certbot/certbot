# Stubs for email.mime.message (Python 3.4)

from email.message import Message
from email.mime.nonmultipart import MIMENonMultipart

class MIMEMessage(MIMENonMultipart):
    def __init__(self, _msg: Message, _subtype: str = ...) -> None: ...
