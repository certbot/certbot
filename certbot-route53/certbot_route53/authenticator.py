"""Certbot Route53 authenticator plugin."""
import logging
import time
import datetime

import zope.interface

import boto3
from botocore.exceptions import NoCredentialsError, ClientError

from acme import challenges

from certbot import interfaces
from certbot.plugins import common


logger = logging.getLogger(__name__)

TTL = 10

INSTRUCTIONS = (
    "To use certbot-route53, configure credentials as described at "
    "https://boto3.readthedocs.io/en/latest/guide/configuration.html#best-practices-for-configuring-credentials "
    "and add the necessary permissions for Route53 access.")

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Route53 Authenticator

    This authenticator solves a DNS01 challenge by uploading the answer to AWS
    Route53.
    """

    description = ("Authenticate domain names using the DNS challenge type, "
        "by automatically updating TXT records using AWS Route53. Works only "
        "if you use AWS Route53 to host DNS for your domains. " +
        INSTRUCTIONS)

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.r53 = boto3.client("route53")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return "Solve a DNS01 challenge using AWS Route53"

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        try:
            change_ids = [
                self._change_txt_record("UPSERT", achall)
                for achall in achalls
            ]

            for change_id in change_ids:
                self._wait_for_change(change_id)
            # Sleep for at least the TTL, to ensure that any records cached by
            # the ACME server after previous validation attempts are gone. In
            # most cases we'll need to wait at least this long for the Route53
            # records to propagate, so this doesn't delay us much.
            time.sleep(TTL)
            return [achall.response(achall.account_key) for achall in achalls]
        except (NoCredentialsError, ClientError) as e:
            e.args = ("\n".join([str(e), INSTRUCTIONS]),)
            raise

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            self._change_txt_record("DELETE", achall)

    def _find_zone_id_for_domain(self, domain):
        """Find the zone id responsible a given FQDN.

           That is, the id for the zone whose name is the longest parent of the
           domain.
        """
        paginator = self.r53.get_paginator("list_hosted_zones")
        zones = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue

                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise ValueError(
                "Unable to find a Route53 hosted zone for {}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the first one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action, achall):
        domain = achall.validation_domain_name(achall.domain)
        value = achall.validation(achall.account_key)

        zone_id = self._find_zone_id_for_domain(domain)

        response = self.r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "certbot-route53 certificate validation " + action,
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": TTL,
                            "ResourceRecords": [
                                # For some reason TXT records need to be
                                # manually quoted.
                                {"Value": '"{}"'.format(value)}
                            ],
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"]

    def _wait_for_change(self, change_id):
        """Wait for a change to be propagated to all Route53 DNS servers.
           https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html
        """
        for n in range(0, 120):
            response = self.r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise Exception(
            "Timed out waiting for Route53 change. Current status: %s" %
            response["ChangeInfo"]["Status"])
