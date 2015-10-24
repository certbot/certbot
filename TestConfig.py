import copy
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


if __name__ == '__main__':
    unittest.main()
