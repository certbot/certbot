"""Route53 Let's Encrypt authenticator plugin."""
import os
import logging
import re
import subprocess

import zope.component
import zope.interface

import boto3

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)

class Authenticator(common.Plugin):
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Route53 Authenticator"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self._httpd = None

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    def _perform_single(self, achall):
        # provision the TXT record, using the domain name given. Assumes the hosted zone exits, else fails the challenge
        response, validation = achall.response_and_validation()
        r53 = boto3.client('route53')
        logger.info("Doing validation for " + response.domain)
        listResponse = r53.list_hosted_zones_by_name(DNSName=response.domain)
        matches = listResponse.HostedZones;
        if matches.size != 0:
            logger.error("Route53 returned " + mathces.size + " matching hosted zones. Expected exactly one. Auth canceled.")
            return None
        else:
            r53.change_resource_record_sets(HostedZoneId=matches[0].Id,
                ChangeBatch={
                'Comment': 'Let\'s Entcrypt Change',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': achall.validation_domain_name(),
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': validation
                                },
                            ]
                        }
                    },
                ]
            })

        if response.simple_verify(
                achall.chall, achall.domain,
                achall.account_key.public_key(), self.config.http01_port):
            return response
        else:
            logger.error(
                "Self-verify of challenge failed, authorization abandoned!")
            return None

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        #TODO:Cleanup record 
        r53 = boto3.client('route53')
        #for achall in achalls:
        #    r53.delete_object(Bucket=self.conf('s3-bucket'), Key=achall.chall.path[1:])
        return None
