  # Phase 2: Create venv, install LE, and run.

  shift 1  # the --le-auto-phase2 arg
  if [ -f "$VENV_BIN/letsencrypt" ]; then
    # --version output ran through grep due to python-cryptography DeprecationWarnings
    # grep for both certbot and letsencrypt until certbot and shim packages have been released
    INSTALLED_VERSION=$("$VENV_BIN/letsencrypt" --version 2>&1 | grep "^certbot\|^letsencrypt" | cut -d " " -f 2)
    if [ -z "$INSTALLED_VERSION" ]; then
        error "Error: couldn't get currently installed version for $VENV_BIN/letsencrypt: " 1>&2
        "$VENV_BIN/letsencrypt" --version
        exit 1
    fi
  else
    INSTALLED_VERSION="none"
  fi
  if [ "$LE_AUTO_VERSION" != "$INSTALLED_VERSION" ]; then
    say "Creating virtual environment..."
    DeterminePythonVersion
    rm -rf "$VENV_PATH"
    if [ "$VERBOSE" = 1 ]; then
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH"
    else
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH" > /dev/null
    fi

    say "Installing Python packages..."
    TEMP_DIR=$(TempDir)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # There is no $ interpolation due to quotes on starting heredoc delimiter.
    # -------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/letsencrypt-auto-requirements.txt"
{{ phase-2/dependency-requirements.txt }}
{{ phase-2/letsencrypt-requirements.txt }}
{{ phase-2/certbot-requirements.txt }}
UNLIKELY_EOF
    # -------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/pipstrap.py"
{{ phase-2/pipstrap.py }}
UNLIKELY_EOF
    # -------------------------------------------------------------------------
    # Set PATH so pipstrap upgrades the right (v)env:
    PATH="$VENV_BIN:$PATH" "$VENV_BIN/python" "$TEMP_DIR/pipstrap.py"
    set +e
    if [ "$VERBOSE" = 1 ]; then
      "$VENV_BIN/pip" install --no-cache-dir --require-hashes -r "$TEMP_DIR/letsencrypt-auto-requirements.txt"
    else
      PIP_OUT=`"$VENV_BIN/pip" install --no-cache-dir --require-hashes -r "$TEMP_DIR/letsencrypt-auto-requirements.txt" 2>&1`
    fi
    PIP_STATUS=$?
    set -e
    if [ "$PIP_STATUS" != 0 ]; then
      # Report error. (Otherwise, be quiet.)
      error "Had a problem while installing Python packages."
      if [ "$VERBOSE" != 1 ]; then
        error
        error "pip prints the following errors: "
        error "====================================================="
        error "$PIP_OUT"
        error "====================================================="
        error
        error "Certbot has problem setting up the virtual environment."

        if `echo $PIP_OUT | grep -q Killed` || `echo $PIP_OUT | grep -q "allocate memory"` ; then
          error
          error "Based on your pip output, the problem can likely be fixed by "
          error "increasing the available memory."
        else
          error
          error "We were not be able to guess the right solution from your pip "
          error "output."
        fi

        error
        error "Consult https://certbot.eff.org/docs/install.html#problems-with-python-virtual-environment"
        error "for possible solutions."
        error "You may also find some support resources at https://certbot.eff.org/support/ ."
      fi
      rm -rf "$VENV_PATH"
      exit 1
    fi
    say "Installation succeeded."
  fi
  if [ -n "$SUDO" ]; then
    # SUDO is su wrapper or sudo
    say "Requesting root privileges to run certbot..."
    say "  $VENV_BIN/letsencrypt" "$@"
  fi
  if [ -z "$SUDO_ENV" ] ; then
    # SUDO is su wrapper / noop
    $SUDO "$VENV_BIN/letsencrypt" "$@"
  else
    # sudo
    $SUDO "$SUDO_ENV" "$VENV_BIN/letsencrypt" "$@"
  fi