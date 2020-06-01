"""This is run during installation to assemble command-line exe launchers

Each launcher contains: exe base + shebang + zipped Python code
"""
import glob
import re
import os
import sys

shebang = '#!"{executable}{suffix}.exe"\r\n'
launchers = [('launcher_exe.dat', '-append.zip', ''),
             ('launcher_noconsole_exe.dat', '-append-noconsole.zip', 'w')]

def assemble_exe(exe_path, b_launcher, b_shebang, b_append):
    with open(exe_path, 'wb') as f:
        f.write(b_launcher)
        f.write(b_shebang)
        f.write(b_append)

def main(argv=None):
    if argv is None:
        argv = sys.argv
    executable = argv[1]
    target_dir = argv[2]

    executable = re.sub(r'\.exe$', '', executable)

    for launcher, append, suffix in launchers:
        b_shebang = shebang.format(executable=executable, suffix=suffix).encode('utf-8')

        with open(os.path.join(target_dir, launcher), 'rb') as f:
            b_launcher = f.read()

        for path in glob.glob(os.path.join(target_dir, '*' + append)):
            with open(path, 'rb') as f:
                b_append = f.read()
            assemble_exe(path[:-len(append)] + '.exe', b_launcher, b_shebang, b_append)

if __name__ == '__main__':
    main()
