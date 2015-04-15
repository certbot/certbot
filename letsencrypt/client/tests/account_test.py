import mock

from letsencrypt.client import account
from letsencrypt.client import configuration


mock_config = mock.MagicMock(spec=configuration.NamespaceConfig)
acc = account.Account.from_prompts(mock_config)

acc.save()