"""Certbot Route53 authenticator plugin."""
import logging
import time
import datetime

import zope.interface

import boto3
from botocore.exceptions import NoCredentialsError

from acme import challenges

from certbot import interfaces
from certbot.plugins import common


logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "To use, create an IAM user and attach the AmazonRoute53FullAccess policy, then store "
    "the access key ID and secret key in ~/.aws/credentials or in "
    "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, as described at "
    "https://boto3.readthedocs.io/en/latest/guide/configuration.html")

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
        session = boto3.Session()
        self.route53_client = session.client("route53")
        # A list of (dns name, TXT value) tuples, for cleanup.
        self.txt_records = []

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return "Solve a DNS01 challenge using AWS Route53"

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        try:
            change_ids = [self._create_single(achall) for achall in achalls]
            for change_id in change_ids:
                self._wait_for_change(change_id)
            return [achall.response(achall.account_key) for achall in achalls]
        except NoCredentialsError:
            raise Exception("No AWS Route53 credentials found. " + INSTRUCTIONS)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for name, value in self.txt_records:
            self._delete_txt_record(name, value)

    def _create_single(self, achall):
        """Create a TXT record, return a change_id"""
        name, value = (achall.validation_domain_name(achall.domain),
            achall.validation(achall.account_key))
        change_id = self._create_txt_record(name, value)
        self.txt_records.append((name, value))
        return change_id

    def _find_zone_id_for_domain(self, domain):
        paginator = self.route53_client.get_paginator("list_hosted_zones")
        zones = []
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if (
                    domain.endswith(zone["Name"]) or
                    (domain + ".").endswith(zone["Name"])
                ) and not zone["Config"]["PrivateZone"]:
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

    def _change_txt_record(self, action, zone_id, domain, value):
        response = self.route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "certbot-route53 certificate validation " + action,
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": 0,
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

    def _create_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record("UPSERT", zone_id, host, value)
        return change_id

    def _delete_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record("DELETE", zone_id, host, value)
        return change_id

    def _wait_for_change(self, change_id):
        deadline = datetime.datetime.now() + datetime.timedelta(minutes=10)
        while datetime.datetime.now() < deadline:
            response = self.route53_client.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise Exception(
            "Timed out waiting for Route53 change. Current status: %s" %
            response["ChangeInfo"]["Status"])
