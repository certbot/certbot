# A COLLECTION OF FUNCTIONS USED BY certbot-auto

say() {
    if [  "$QUIET" != 1 ]; then
        echo "$@"
    fi
}

error() {
    echo "$@"
}

# certbot-auto needs root access to bootstrap OS dependencies, and
# certbot itself needs root access for almost all modes of operation
# The "normal" case is that sudo is used for the steps that need root, but
# this script *can* be run as root (not recommended), or fall back to using
# `su`. Auto-detection can be overridden by explicitly setting the
# environment variable LE_AUTO_SUDO to 'sudo', 'sudo_su' or '' as used below.

# Because the parameters in `su -c` has to be a string,
# we need to properly escape it.
su_sudo() {
  args=""
  # This `while` loop iterates over all parameters given to this function.
  # For each parameter, all `'` will be replace by `'"'"'`, and the escaped string
  # will be wrapped in a pair of `'`, then appended to `$args` string
  # For example, `echo "It's only 1\$\!"` will be escaped to:
  #   'echo' 'It'"'"'s only 1$!'
  #     │       │└┼┘│
  #     │       │ │ └── `'s only 1$!'` the literal string
  #     │       │ └── `\"'\"` is a single quote (as a string)
  #     │       └── `'It'`, to be concatenated with the strings following it
  #     └── `echo` wrapped in a pair of `'`, it's totally fine for the shell command itself
  while [ $# -ne 0 ]; do
    args="$args'$(printf "%s" "$1" | sed -e "s/'/'\"'\"'/g")' "
    shift
  done
  su root -c "$args"
}

DeterminePythonVersion() {
  for LE_PYTHON in "$LE_PYTHON" python2.7 python27 python2 python; do
    # Break (while keeping the LE_PYTHON value) if found.
    $EXISTS "$LE_PYTHON" > /dev/null && break
  done
  if [ "$?" != "0" ]; then
    error "Cannot find any Pythons; please install one!"
    exit 1
  fi
  export LE_PYTHON

  PYVER=`"$LE_PYTHON" -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`
  if [ "$PYVER" -lt 26 ]; then
    error "You have an ancient version of Python entombed in your operating system..."
    error "This isn't going to work; you'll need at least version 2.6."
    exit 1
  fi
}

TempDir() {
  mktemp -d 2>/dev/null || mktemp -d -t 'le'  # Linux || macOS
}