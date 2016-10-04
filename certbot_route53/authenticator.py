"""Route53 Let's Encrypt authenticator plugin."""
import logging
import time

import zope.interface

import boto3

from acme import challenges

from certbot import interfaces
from certbot.plugins import common


logger = logging.getLogger(__name__)

TTL = 30

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

    def _find_zone(self, r53, domain):
        return max(
            (
                zone for zone in r53.list_hosted_zones()["HostedZones"]
                if (domain+".").endswith("."+zone["Name"])
            ),
            key=lambda zone: len(zone["Name"]),
        )


    def _perform_single(self, achall):
        # provision the TXT record, using the domain name given. Assumes the hosted zone exits, else fails the challenge
        r53 = boto3.client('route53')
        logger.info("Doing validation for " + achall.domain)

        try:
            zone = self._find_zone(r53, achall.domain)
        except ValueError as e:
            logger.error("Unable to find matching Route53 zone for domain " + achall.domain)
            return None

        response, validation = achall.response_and_validation()
        self._excute_r53_action(r53, achall, zone, validation, 'UPSERT', wait_for_change=True)

        for _ in xrange(TTL*2):
            if response.simple_verify(
                achall.chall,
                achall.domain,
                achall.account_key.public_key(),
            ):
                break
            logger.info("Waiting for DNS propagation...")
            time.sleep(1)
        else:
            logger.error("Unable to verify domain " + achall.domain)
            return None

        return response

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring
        r53 = boto3.client('route53')
        for achall in achalls:
            try:
                zone = self._find_zone(r53, achall.domain)
            except ValueError:
                logger.warn("Unable to find zone for " + achall.domain + ". Skipping cleanup.")
                continue

            _, validation = achall.response_and_validation()
            self._excute_r53_action(r53, achall, zone, validation, 'DELETE')
        return None


    def _excute_r53_action(self, r53, achall, zone, validation, action, wait_for_change=False):
            response = r53.change_resource_record_sets(
                HostedZoneId=zone["Id"],
                ChangeBatch={
                    'Comment': 'Let\'s Encrypt ' + action,
                    'Changes': [
                        {
                            'Action': action,
                            'ResourceRecordSet': {
                                'Name': achall.validation_domain_name(achall.domain),
                                'Type': 'TXT',
                                'TTL': TTL,
                                'ResourceRecords': [
                                    {
                                        'Value': '"' + validation + '"',
                                    },
                                ],
                            },
                        },
                    ],
                },
            )

            if wait_for_change:
                while r53.get_change(Id=response["ChangeInfo"]["Id"])["ChangeInfo"]["Status"] == "PENDING":
                    logger.info("Waiting for " + action + " to propagate...")
                    time.sleep(1)
