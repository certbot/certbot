BootstrapAlpineCommon() {
  # Tested with:
  #   - Alpine 3.4

  $SUDO apk update || echo apk update hit problems but continuing anyway...

  $SUDO apk add --no-progress --virtual .virtualenv-deps \
            python \
            python-dev \
            py-pip \
            build-base

  $SUDO pip install virtualenv

  $SUDO apk add --no-progress --virtual .certbot-deps \
           dialog \
           augeas-libs \
           libffi \
           libssl1.0 \
           wget \
           ca-certificates \
           binutils

  $SUDO apk add --no-progress --virtual .build-deps \
           gcc \
           linux-headers \
           openssl-dev \
           musl-dev \
           libffi-dev

}