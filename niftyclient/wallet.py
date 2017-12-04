import requests
from . import schema
from .client_base import ClientBase


class Wallet(ClientBase):

    @property
    def wallet_url(self):
        return '{self.user_url}/wallet'.format(self=self)

    def get_wallet(self):
        """
        Fetch the wallet details. If there's no wallet,
        the response will be an empty list Otherwise,
        return the existing wallet
        """
        response = requests.get(
            self.wallet_url, auth=self.auth, headers=self.headers)
        return self.process_response(response, schema.WalletSchema())

    def create_wallet(self):
        """
        Create the wallet if it doesn't exist and return it.
        Otherwise return the existing wallet
        """
        response = requests.post(
            self.wallet_url, auth=self.auth, headers=self.headers)
        return self.process_response(response, schema.WalletSchema())
