class IntegrationTestsContext:
    """General fixture describing a certbot integration tests context"""
    def __init__(self, request):
        self.request = request
        self.worker_id = request.config.slaveinput['slaveid']\
            if hasattr(request.config, 'slaveinput') else 'primary'
        self.directory_url = request.config.acme_xdist['directory_url']
        self.tls_alpn_01_port = request.config.acme_xdist['https_port'][self.worker_id]
        self.http_01_port = request.config.acme_xdist['http_port'][self.worker_id]

    def cleanup(self):
        pass
