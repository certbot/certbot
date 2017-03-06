"""Manual test of display functions."""
import sys

from certbot.display import util
from certbot.tests.display import util_test


def test_visual(displayer, choices):
    """Visually test all of the display functions."""
    displayer.notification("Random notification!")
    displayer.menu("Question?", choices,
                   ok_label="O", cancel_label="Can", help_label="??")
    displayer.menu("Question?", [choice[1] for choice in choices],
                   ok_label="O", cancel_label="Can", help_label="??")
    displayer.input("Input Message")
    displayer.yesno("YesNo Message", yes_label="Yessir", no_label="Nosir")
    displayer.checklist("Checklist Message", [choice[0] for choice in choices])


if __name__ == "__main__":
    displayer = util.FileDisplay(sys.stdout, False)
    test_visual(displayer, util_test.CHOICES)
