#!/bin/sh

DEFAULT_CONF=/etc/postfix/main.cf
BACKUP_TLS_CONF=/etc/postfix/tls.cf.bk
BACKUP_NO_TLS_CONF=/etc/postfix/no_tls.cf.bk

setup() {
    ### Certbot setup
    ln -sf "/opt/certbot-postfix/testdata/certificates" /etc/certificates

    # Postconf things for testing purposes.
    postconf -e smtpd_use_tls=no
    postconf -e smtpd_tls_received_header=yes
    postconf -e smtputf8_enable=no
    postconf -e disable_dns_lookups=yes
    postconf -e myhostname=$HOSTNAME
    newaliases

    cat /etc/certificates/ca.crt >> /etc/ssl/certs/ca-certificates.crt
}

install_certs() {
    # If certs alrady installed, restore from backup.
    if ! [ -f $BACKUP_NO_TLS_CONF ]; then
        cp $DEFAULT_CONF $BACKUP_NO_TLS_CONF
    fi

    # Install certs via certbot!
    cert_name=$1
    shift
    certbot install --installer postfix \
        --cert-path /etc/certificates/$cert_name.crt --key-path /etc/certificates/$cert_name.key \
        -d recipient.com ${@}
}

uninstall_certs() {
    # We shouldn't have to do anything other than
    # restore the original backup version.
    if [ -f $BACKUP_NO_TLS_CONF ]; then
        cp $BACKUP_NO_TLS_CONF $DEFAULT_CONF
        postfix reload
        exit 0
    fi
}
