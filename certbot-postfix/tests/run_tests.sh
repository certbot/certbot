#!/bin/sh

set -e

RCPTNAME=recipient
SENDNAME=sender
NETWORKNAME=certbot_postfix_network
IMAGE_NAME=certbot_postfix
BASE_IMAGE=certbot_local

# Create network if it doesn't exist
docker network create -d bridge $NETWORKNAME || true

# Build with all the changes.
# TODO: when changes from this branch land in master,
# we no longer need to re-build the base image.
docker build -t $BASE_IMAGE -f ../Dockerfile ../
docker build -t $IMAGE_NAME .

# Run sender and receipient images
docker stop $SENDNAME || true
docker stop $RCPTNAME || true

docker run --rm --network=$NETWORKNAME \
    -itd --name $SENDNAME -h $SENDNAME -p 25 $IMAGE_NAME
    
docker run --rm --network=$NETWORKNAME \
    -itd --name $RCPTNAME -h $RCPTNAME -p 25 $IMAGE_NAME

docker_do() {
    docker exec ${1} /bin/sh -c ". ./tests/setup.sh && ${2}"
}

sender_do() {
    docker_do $SENDNAME "$1"
}

recipient_do() {
    docker_do $RCPTNAME "$1"
}

both_do() {
    sender_do "$1" && recipient_do "$1"
}

both_do "setup && install_certs valid"

echo "Regular mail over TLS..."
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sleep 1
recipient_do "cat /var/mail/root | grep \"TLS\""

echo "Mail NOT sent over TLS..."
recipient_do "rm /var/mail/root"
recipient_do uninstall_certs
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
recipient_do "[ -f /var/mail/root ] && ! (cat /var/mail/root | grep \"TLS\")"

echo "Mail NOT sent over TLS if policy configured poorly..."
sender_do "install_certs valid --starttls-policy /opt/certbot-postfix/testdata/recipient_policy.json"
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sender_do "mailq | grep \"TLS is required, but was not offered\""

echo "Mail NOT sent over TLS if cert name wrong..."
recipient_do "install_certs evil"
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sender_do "mailq | grep \"Server certificate not verified\""

echo "Mail NOT sent over TLS if certs root not trusted..."
recipient_do "install_certs self-signed"
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sender_do "mailq | grep \"Server certificate not trusted\""

echo "Mail sent over TLS if policy configured properly..."
recipient_do "install_certs valid"
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sleep 1
recipient_do "cat /var/mail/root | grep \"TLS\""

