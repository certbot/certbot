#!/usr/bin/env python
import copy
import itertools
import logging
import unittest

import Config

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


class TestTLSPolicy(unittest.TestCase):

    def setUp(self):
        self.old_config = Config.TLSPolicy(domain_suffix='.eff.org')
        self.old_config.comment = 'Testing EFF.org TLS policy'
        self.old_config.require_tls = True
        self.old_config.require_valid_certificate = False
        self.old_config.min_tls_version = 'TLSv1'
        self.old_config.enforce_mode = 'log-only'

        self.new_config = Config.TLSPolicy(domain_suffix='.eff.org') 
        self.new_config.require_valid_certificate = True
        self.new_config.min_tls_version = 'TLSv1.2'
        self.new_config.enforce_mode = 'enforce'

    def testUpdateDropsOldSettings(self):
        logger.debug('old: %s' % self.old_config)
        logger.debug('new: %s' % self.new_config)
        tls_policy = self.old_config.update(self.new_config)
        logger.debug('just generated: %s' % tls_policy)
        self.assertFalse(any([tls_policy.require_tls, tls_policy.comment]))

    def testMergeKeepsOldSettings(self):
        logger.debug('old: %s' % self.old_config)
        logger.debug('new: %s' % self.new_config)
        tls_policy = self.old_config.merge(self.new_config, merge=True)
        logger.debug('just generated: %s' % tls_policy)
        self.assertTrue(all([tls_policy.require_tls, tls_policy.comment]))

    def testUpdateGetsNameSet(self):
        tls_policy = self.old_config.update(self.new_config)
        self.assertEquals(tls_policy.domain_suffix, self.old_config.domain_suffix)


class TestAcceptableMX(unittest.TestCase):

    def setUp(self):
        self.old_config = Config.AcceptableMX(domain='eff.org')
        self.old_config.add_acceptable_mx('.eff.org')

    def testUpdateDropsOldMXs(self):
        new_bogus_mx = '.testing.eff.org'
        new_config = Config.AcceptableMX(domain='eff.org')
        new_config.add_acceptable_mx(new_bogus_mx)
        updated_config = self.old_config.update(new_config)
        self.assertNotIn('.eff.org', updated_config.accept_mx_domains)

    def testMergeKeepsOldMXs(self):
        new_bogus_mx = '.testing.eff.org'
        new_config = Config.AcceptableMX(domain='eff.org')
        new_config.add_acceptable_mx(new_bogus_mx)
        updated_config = self.old_config.merge(new_config)
        self.assertListEqual(sorted(['.eff.org', '.testing.eff.org']),
                             sorted(updated_config.accept_mx_domains))

    def testUpdateGetsNameSet(self):
        new_policy = Config.AcceptableMX(domain=self.old_config.domain)
        mx_policy = self.old_config.update(new_policy)
        self.assertEquals(mx_policy.domain, self.old_config.domain)


class TestConfig(unittest.TestCase):
    """Test entire configuration.

    Currently lower coverage is being obtained since string sets are
    being compared rather than returned objects. Comparison logic for
    the config objects isn't clear yet and proof that they function is enough.
    """

    def setUp(self):
        self.config = Config.Config()
        domain_policies = self.config._data['acceptable-mxs']
        self.mail_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', '123.cn', 'qq.com']
        for domain in self.mail_domains:
            new = Config.AcceptableMX(domain=domain)
            new.add_acceptable_mx('.' + domain)
            domain_policies[domain] = new

    def testGetAllMxItems(self):
        """Make sure the basic use case of get_all_mx_items functions."""
        # [ ('.gmail.com', 'gmail.com'), ('.yahoo.com', 'yahoo.com'), ... ]
        control_data = [ ('.' + domain, domain) for domain in self.mail_domains ]
        test_data = [ (mx, p.domain) for mx, p in self.config.get_all_mx_items() ]
        self.assertListEqual(sorted(test_data), sorted(control_data))

    def testGetAllMxItemsMultiMX(self):
        config = copy.deepcopy(self.config)
        domain_policy = config.acceptable_mxs.get('gmail.com')
        # deal with reality, mail.google.com
        domain_policy.add_acceptable_mx('.mail.google.com')
        control_data = [ ('.' + domain, domain) for domain in self.mail_domains ]
        control_data.append(('.mail.google.com', 'gmail.com'))
        test_data = [ (mx, p.domain) for mx, p in config.get_all_mx_items() ]
        self.assertListEqual(sorted(test_data), sorted(control_data))

    def testGetMXtoDomainPolicy(self):
        control_data = dict([ ('.' + domain, set([domain]))
                             for domain in self.mail_domains ])
        test_data = {}
        for mx, pset in self.config.get_mx_to_domain_policy_map().items():
            policy_list = [ p.domain for p in pset ]
            test_data[mx] = set(policy_list)
        self.assertDictEqual(test_data, control_data)

    def testGetMXtoDomainPolicyMultiMX(self):
        config = copy.deepcopy(self.config)
        domain_policy = config.acceptable_mxs.get('gmail.com')
        domain_policy.add_acceptable_mx('.mail.google.com')
        control_data = dict([ ('.' + domain, set([domain]))
                            for domain in self.mail_domains ])
        control_data['.mail.google.com'] = set(['gmail.com'])
        test_data = {}
        for mx, pset in config.get_mx_to_domain_policy_map().items():
            policy_list = [ p.domain for p in pset ]
            test_data[mx] = set(policy_list)
        self.assertDictEqual(test_data, control_data)


if __name__ == '__main__':
    unittest.main()
