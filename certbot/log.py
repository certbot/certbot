"""Logging utilities."""
import logging

import dialog

from certbot.display import util as display_util


class DialogHandler(logging.Handler):  # pylint: disable=too-few-public-methods
    """Logging handler using dialog info box.

    :ivar int height: Height of the info box (without padding).
    :ivar int width: Width of the info box (without padding).
    :ivar list lines: Lines to be displayed in the info box.
    :ivar d: Instance of :class:`dialog.Dialog`.

    """

    PADDING_HEIGHT = 2
    PADDING_WIDTH = 4

    def __init__(self, level=logging.NOTSET, height=display_util.HEIGHT,
                 width=display_util.WIDTH - 4, d=None):
        # Handler not new-style -> no super
        logging.Handler.__init__(self, level)
        self.height = height
        self.width = width
        # "dialog" collides with module name...
        self.d = dialog.Dialog() if d is None else d
        self.lines = []

    def emit(self, record):
        """Emit message to a dialog info box.

        Only show the last (self.height) lines; note that lines can wrap
        at self.width, so a single line could actually be multiple
        lines.

        """
        for line in self.format(record).splitlines():
            # check for lines that would wrap
            cur_out = line
            while len(cur_out) > self.width:
                # find first space before self.width chars into cur_out
                last_space_pos = cur_out.rfind(' ', 0, self.width)

                if last_space_pos == -1:
                    # no spaces, just cut them off at whatever
                    self.lines.append(cur_out[0:self.width])
                    cur_out = cur_out[self.width:]
                else:
                    # cut off at last space
                    self.lines.append(cur_out[0:last_space_pos])
                    cur_out = cur_out[last_space_pos + 1:]
            if cur_out != '':
                self.lines.append(cur_out)

        # show last 16 lines
        content = '\n'.join(self.lines[-self.height:])

        # add the padding around the box
        self.d.infobox(
            content, self.height + self.PADDING_HEIGHT,
            self.width + self.PADDING_WIDTH)
