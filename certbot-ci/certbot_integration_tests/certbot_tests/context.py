class IntegrationTestsContext(object):
    """General fixture describing a certbot integration tests context"""
    def __init__(self, request):
        self.request = request
        if hasattr(request.config, 'slaveinput'):  # Worker node
            self.worker_id = request.config.slaveinput['slaveid']
            self.acme_xdist = request.config.slaveinput['acme_xdist']
        else:  # Primary node
            self.worker_id = 'primary'
            self.acme_xdist = request.config.acme_xdist
        self.directory_url = self.acme_xdist['directory_url']
        self.tls_alpn_01_port = self.acme_xdist['https_port'][self.worker_id]
        self.http_01_port = self.acme_xdist['http_port'][self.worker_id]

    def cleanup(self):
        pass
