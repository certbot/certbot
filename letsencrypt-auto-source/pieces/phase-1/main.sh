  # Phase 1: Upgrade certbot-auto if necessary, then self-invoke.
  #
  # Each phase checks the version of only the thing it is responsible for
  # upgrading. Phase 1 checks the version of the latest release of
  # certbot-auto (which is always the same as that of the certbot
  # package). Phase 2 checks the version of the locally installed certbot.

  if [ ! -f "$VENV_BIN/letsencrypt" ]; then
    if [ "$HELP" = 1 ]; then
      echo "$USAGE"
      exit 0
    fi
    # If it looks like we've never bootstrapped before, bootstrap:
    Bootstrap
  fi
  if [ "$OS_PACKAGES_ONLY" = 1 ]; then
    say "OS packages installed."
    exit 0
  fi

  if [ "$NO_SELF_UPGRADE" != 1 ]; then
    TEMP_DIR=$(TempDir)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # ---------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/fetch.py"
{{ phase-1/fetch.py }}
UNLIKELY_EOF
    # ---------------------------------------------------------------------------
    DeterminePythonVersion
    if ! REMOTE_VERSION=`"$LE_PYTHON" "$TEMP_DIR/fetch.py" --latest-version` ; then
      error "WARNING: unable to check for updates."
    elif [ "$LE_AUTO_VERSION" != "$REMOTE_VERSION" ]; then
      say "Upgrading certbot-auto $LE_AUTO_VERSION to $REMOTE_VERSION..."

      # Now we drop into Python so we don't have to install even more
      # dependencies (curl, etc.), for better flow control, and for the option of
      # future Windows compatibility.
      "$LE_PYTHON" "$TEMP_DIR/fetch.py" --le-auto-script "v$REMOTE_VERSION"

      # Install new copy of certbot-auto.
      # TODO: Deal with quotes in pathnames.
      say "Replacing certbot-auto..."
      # Clone permissions with cp. chmod and chown don't have a --reference
      # option on macOS or BSD, and stat -c on Linux is stat -f on macOS and BSD:
      $SUDO cp -p "$0" "$TEMP_DIR/letsencrypt-auto.permission-clone"
      $SUDO cp "$TEMP_DIR/letsencrypt-auto" "$TEMP_DIR/letsencrypt-auto.permission-clone"
      # Using mv rather than cp leaves the old file descriptor pointing to the
      # original copy so the shell can continue to read it unmolested. mv across
      # filesystems is non-atomic, doing `rm dest, cp src dest, rm src`, but the
      # cp is unlikely to fail (esp. under sudo) if the rm doesn't.
      $SUDO mv -f "$TEMP_DIR/letsencrypt-auto.permission-clone" "$0"
    fi  # A newer version is available.
  fi  # Self-upgrading is allowed.

  "$0" --le-auto-phase2 "$@"