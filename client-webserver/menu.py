#!/usr/bin/env python

import dialog, getopt, sys

def filter_names(names):
    d = dialog.Dialog()
    choices = [(n, "", 1) for n in names]
    result = d.checklist("Which names would you like to activate HTTPS for?", choices=choices)
    if result[0] != 0 or not result[1]:
        sys.exit(1)
    return result[1]

def by_default():
    d = dialog.Dialog()
    choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
    result = d.menu("Please choose whether HTTPS access is required or optional.", width=70, choices=choices)
    if result[0] != 0:
        sys.exit(1)
    return result[1] == "Secure"
