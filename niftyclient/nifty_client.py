import logging
from .c2b import C2B
from .wallet import Wallet
from .online_checkout import OnlineCheckout


class NiftyClient(object):
    def __init__(self, config, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.c2b = C2B(config, self.logger)
        self.wallet = Wallet(config, self.logger)
        self.online_checkout = OnlineCheckout(config, self.logger)
