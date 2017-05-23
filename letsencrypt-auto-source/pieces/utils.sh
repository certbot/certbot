TempDir() {
  mktemp -d 2>/dev/null || mktemp -d -t 'le'  # Linux || macOS
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