from command import Command
import errno
import heroku3
import certbot_heroku.heroku3_extended

certbot_heroku.heroku3_extended.extend(heroku3)

class HerokuCLI(object):
    def __init__(self, logger, dry_run=False):
        self.logger = logger
        self.dry_run = dry_run
    
    def heroku(self, *args):
        command = Command('heroku', *args).resudoed()
        command.on_returncode(2, raises=HerokuCLI.NoSuchRemoteError)
        return command
    
    def is_installed(self):
        try:
            self.heroku("version").run(logger=self.logger)
            return True
        except Command.NotInstalledError:
            return False
    
    def get_token(self):
        return self.heroku("auth:token").capture(logger=self.logger).rstrip()
    
    def get_app_name(self, remote):
        output = self.heroku("apps:info", "--remote", remote).capture(logger=self.logger)
        app_name_line = filter(lambda line: line.startswith("=== "), output.splitlines())[0]
        
        return app_name_line[3:].strip()
    
    class NoSuchRemoteError(Command.ProcessError):
        def __str__(self):
            return "Remote " + self.command.arguments[-1] + " does not exist."

class HerokuApp(object):
    def __init__(self, token, app_name, dry_run, logger):
        self._api = heroku3.from_key(token)
        self._api_app = self._api.app(app_name)
        self._dry_run = dry_run
        self._logger = logger
    
    def get_domains(self):
        domain_objs = self._api_app.domains()
        
        # The kind field is in Heroku's docs, but doesn't come through here for some reason
        # custom_domain_objs = filter(lambda d: d.kind == "custom", domain_objs)
        custom_domain_objs = filter(lambda d: not d.hostname.endswith(".herokuapp.com"), domain_objs)
        
        return map(lambda d: d.hostname, custom_domain_objs)
    
    def update_certificate(self, key, certificate):
        ssls = self._api_app.ssl_endpoints()
        
        num_endpoints = len(ssls)
        if num_endpoints != 1:
            raise HerokuApp.UncertainSSLEndpointError(num_endpoints=num_endpoints)
        ssl = ssls[0]
        
        if self._dry_run:
            self._logger.warning("Would replace certificate on endpoint " + ssl.name + " with " + certificate)
        else:
            ssl.update(certificate_chain=certificate, private_key=key)
    
    class UncertainSSLEndpointError(Exception):
        def __init__(self, num_endpoints):
            self.num_endpoints = num_endpoints
        
        def __str__(self):
            "The application has " + self.num_endpoint + " endpoints, not 1."
