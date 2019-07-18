FROM certbot/certbot

ARG PLUGIN_NAME

# Retrieve Certbot DNS plugin code
RUN wget -O certbot-${CERTBOT_VERSION}.tar.gz https://github.com/certbot/certbot/archive/v${CERTBOT_VERSION}.tar.gz \
 && tar xf certbot-${CERTBOT_VERSION}.tar.gz \
 && cp -r certbot-${CERTBOT_VERSION}/certbot-${PLUGIN_NAME} /opt/certbot/src/certbot-${PLUGIN_NAME} \
 && rm -rf certbot-${CERTBOT_VERSION}.tar.gz certbot-${CERTBOT_VERSION} 

# Install the DNS plugin
RUN pip install --constraint /opt/certbot/docker_constraints.txt --no-cache-dir --editable /opt/certbot/src/certbot-${PLUGIN_NAME}
