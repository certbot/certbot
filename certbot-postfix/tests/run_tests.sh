#!/bin/sh

set -e

RCPTNAME=recipient
SENDNAME=sender
NETWORKNAME=certbot_postfix_network
IMAGE_NAME=certbot_postfix

# Create network if it doesn't exist
docker network create -d bridge $NETWORKNAME || true

docker build -t $IMAGE_NAME .

# Run sender and receipient images
docker stop $SENDNAME
docker stop $RCPTNAME

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

both_do "setup && install_certs"

echo "Regular mail over TLS..."
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
recipient_do "cat /var/mail/root | grep \"TLS\""

echo "Mail NOT sent over TLS..."
recipient_do "rm /var/mail/root"
recipient_do uninstall_certs
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
recipient_do "[ -f /var/mail/root ] && ! (cat /var/mail/root | grep \"TLS\")"

echo "Mail sent over TLS if policy configured..."
both_do install_certs
sender_do "set_policy \"recipient    encrypt\""
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
recipient_do "cat /var/mail/root | grep \"TLS\""

echo "Mail NOT sent over TLS if policy configured poorly..."
recipient_do uninstall_certs
sender_do "echo -e 'Subject: Subject\n\nbody' | sendmail root@${RCPTNAME}"
sender_do mailq

