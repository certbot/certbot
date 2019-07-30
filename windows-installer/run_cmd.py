"""Start a cmd in a new window, with admin rights (required by Certbot to create symlinks)"""
import subprocess
import ctypes
import sys

def main():
    if ctypes.windll.shell32.IsUserAnAdmin():
        # Already with admin rights, run directly cmd
        subprocess.Popen('start /wait cmd /k "'
                        '  echo +---------------------------------------------------------------+'
                        '& echo ^# Welcome to Certbot.                                           ^#'
                        '& echo ^# Please type \'certbot --help\' to find every available actions. ^#'
                        '& echo +---------------------------------------------------------------+"',
                        shell=True)
    else:
        # No admin rights, invoke again this script with an admin rights request
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

if __name__ == '__main__':
    main()
