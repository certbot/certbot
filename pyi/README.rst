PyInstaller setup for the Let's Encrypt Client.

Firstly, install deps::

  pip install -r requirements.txt

You can then create the binaries by running::

  make clean all

One-file output binary is in ./dist/letsencrypt, one-folder is in
./dist/folder. You can quickly test it both by running::

  ./test.sh -a manual auth

For more info about PyInstaller please see http://pyinstaller.org.
