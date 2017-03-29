def init_le_client(config, authenticator, installer):
    if authenticator is not None:
        # if authenticator was given, then we will need account...
        acc, acme = _determine_account(config)
        logger.debug("Picked account: %r", acc)
        # XXX
        #crypto_util.validate_key_csr(acc.key)
    else:
        acc, acme = None, None

    return client.Client(config, acc, authenticator, installer, acme=acme)

def get_and_save_cert(le_client, config, domains=None, certname=None, lineage=None):
    """Authenticate and enroll certificate.

    This method finds the relevant lineage, figures out what to do with it,
    then performs that action. Includes calls to hooks, various reports,
    checks, and requests for user input.

    :returns: the issued certificate or `None` if doing a dry run
    :rtype: `storage.RenewableCert` or `None`
    """
    hooks.pre_hook(config)
    try:
        if lineage is not None:
            # Renewal, where we already know the specific lineage we're
            # interested in
            logger.info("Renewing an existing certificate")
            renewal.renew_cert(config, domains, le_client, lineage)
        else:
            # TREAT AS NEW REQUEST
            assert domains is not None
            logger.info("Obtaining a new certificate")
            lineage = le_client.obtain_and_enroll_certificate(domains, certname)
            if lineage is False:
                raise errors.Error("Certificate could not be obtained")
    finally:
        hooks.post_hook(config)

    return lineage

def csr_get_and_save_cert(config, le_client):
    """Obtain a cert using a user-supplied CSR

    This works differently in the CSR case (for now) because we don't
    have the privkey, and therefore can't construct the files for a lineage.
    So we just save the cert & chain to disk :/
    """
    csr, typ = config.actual_csr
    certr, chain = le_client.obtain_certificate_from_csr(config.domains, csr, typ)
    if config.dry_run:
        logger.debug(
            "Dry run: skipping saving certificate to %s", config.cert_path)
        return None, None
    cert_path, _, fullchain_path = le_client.save_certificate(
            certr, chain, config.cert_path, config.chain_path, config.fullchain_path)
    return cert_path, fullchain_path

def install_cert(config, le_client, domains, lineage=None):
    path_provider = lineage if lineage else config
    assert path_provider.cert_path is not None

    le_client.deploy_certificate(domains, path_provider.key_path,
        path_provider.cert_path, path_provider.chain_path, path_provider.fullchain_path)
    le_client.enhance_config(domains, path_provider.chain_path)