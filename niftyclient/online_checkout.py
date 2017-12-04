import requests
from . import schema
from .client_base import ClientBase


class OnlineCheckout(ClientBase):

    @property
    def online_checkout_url(self):
        return '{self.user_url}/mpesa/online-checkout'.format(self=self)

    def list_transactions(self, **kwargs):
        """
        List or search Online Checkout Transactions
        Args (All optional):
            payment_id     - Payment id
            phone_number   - Phone number to look up (Format: E.164).
            service_reference_id - Service reference to look up

        Example:
            list_transactions()
            list_transactions(payment_id='871559E4-BED1-4E0C-A4B0-FBD2A5833E00',
                              phone_number='25470000000')

        """
        data = kwargs
        response = requests.get(
            self.online_checkout_url, auth=self.auth,
            headers=self.headers, params=data)
        return self.process_response(
            response, schema.OnlineCheckoutTransactionSchema())

    def initiate_checkout(self, **kwargs):
        """
        Iniate an online checkout transaction.

        Args:
          Required:
            transaction_amount  - Amount to request.
            phone_number        - Phone number of subscriber (Format: E.164).

          Optional:
            transaction_id       - A unique transaction id
            service_reference_id - A means for a merchant to group related transactions  # noqa
            callback_url         -  URL on merchant side to post transaction status

        Example:
            initiate_checkout(
                phone_number='254700000000', transaction_amount=200.00,
                transaction_id= '0xdeadbeef', service_reference_id='user-bovine',
                callback_url='http://merchant.co.ke/callback/oc/trx/0xdeadbeef')
        """
        data = kwargs
        response = requests.post(
            self.online_checkout_url,
            auth=self.auth, headers=self.headers, json=data)
        return self.process_response(
            response, schema.OnlineCheckoutTransactionSchema())
