def extend(heroku3):
    # heroku3 provides no way to access a KeyedListResource's length.

    def _keyed_list_resource_len_method(self):
        return len(self._items)

    heroku3.structures.KeyedListResource.__len__ = _keyed_list_resource_len_method


    # heroku3 does not provide access to the ssl-endpoints resource.

    class SSLEndpoint(heroku3.models.BaseResource):
        _strs = ['certificate_chain', 'cname', 'id', 'name']
        _dates = ['created_at', 'updated_at']
    
        def __init__(self):
            self.app = None
            super(SSLEndpoint, self).__init__()

        def __repr__(self):
            return "<ssl-endpoint '{0} - {1}'>".format(self.name, self.id)
    
        def update(self, certificate_chain = None, private_key = None, preprocess = None, rollback = None):
            payload = dict(certificate_chain=certificate_chain, private_key=private_key, preprocess=preprocess, rollback=rollback)
            for key in payload.keys():
                if payload[key] is None:
                    del payload[key]
        
            r = self._h._http_resource(
                method='PATCH',
                resource=('apps', self.app.name, 'ssl-endpoints', self.name),
                data=self._h._resource_serialize(payload)
            )
        
            r.raise_for_status()
            item = self._h._resource_deserialize(r.content.decode("utf-8"))
            return SSLEndpoint.new_from_dict(item, h=self._h, app=self.app)
    
        def remove(self):
            r = self._h._http_resource(
                method='DELETE',
                resource=('apps', self.app.name, 'ssl-endpoints', self.name)
            )

            r.raise_for_status()

            return r.ok

    def _ssl_endpoints_method(self, **kwargs):
        return self._h._get_resources(
            resource=('apps', self.name, 'ssl-endpoints'),
            obj=SSLEndpoint, app=self, **kwargs
        )

    heroku3.models.app.App.ssl_endpoints = _ssl_endpoints_method
