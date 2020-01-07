"""
Certbot PyLint plugin.

The built-in ImportChecker of Pylint does a similar job to ForbidStandardOsModule to detect
deprecated modules. You can check its behavior as a reference to what is coded here.
See https://github.com/PyCQA/pylint/blob/b20a2984c94e2946669d727dbda78735882bf50a/pylint/checkers/imports.py#L287
See http://docs.pylint.org/plugins.html
"""
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

# Modules in theses packages can import the os module.
WHITELIST_PACKAGES = ['acme', 'certbot_compatibility_test', 'letshelp_certbot', 'lock_test']


class ForbidStandardOsModule(BaseChecker):
    """
    This checker ensures that standard os module (and submodules) is not imported by certbot
    modules. Otherwise a 'os-module-forbidden' error will be registered for the faulty lines.
    """
    __implements__ = IAstroidChecker

    name = 'forbid-os-module'
    msgs = {
        'E5001': (
            'Forbidden use of os module, certbot.compat.os must be used instead',
            'os-module-forbidden',
            'Some methods from the standard os module cannot be used for security reasons on Windows: '
            'the safe wrapper certbot.compat.os must be used instead in Certbot.'
        )
    }
    priority = -1

    def visit_import(self, node):
        os_used = any(name for name in node.names if name[0] == 'os' or name[0].startswith('os.'))
        if os_used and not _check_disabled(node):
            self.add_message('os-module-forbidden', node=node)

    def visit_importfrom(self, node):
        if node.modname == 'os' or node.modname.startswith('os.') and not _check_disabled(node):
            self.add_message('os-module-forbidden', node=node)


def register(linter):
    """Pylint hook to auto-register this linter"""
    linter.register_checker(ForbidStandardOsModule(linter))


def _check_disabled(node):
    module = node.root()
    return any(package for package in WHITELIST_PACKAGES
               if module.name.startswith(package + '.') or module.name == package)
