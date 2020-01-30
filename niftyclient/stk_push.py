import requests
from . import schema
from .client_base import ClientBase


class StkPush(ClientBase):
    @property
    def stkpush_url(self):
        return '{self.user_url}/mpesa/stkpush'.format(self=self)

    def list_transactions(self, **kwargs):
        """
        List or search STKPush Transactions
        Args (All optional):
            merchant_transaction_id - A unique id
            phone_number   - Phone number to look up (Format: E.164).

        Example:
            list_transactions()
            list_transactions(
                merchant_request_id='871559E4-BED1-4E0C-A4B0-FBD2A5833E00',
                phone_number='25470000000')

        """
        data = kwargs
        response = requests.get(
            self.stkpush_url,
            auth=self.auth,
            headers=self.headers,
            params=data)
        return self.process_response(
            response,
            schema.StkPushTransactionSchema())

    def get_stkpush_transaction_url(self, payment_id):
        return "/".join([self.stkpush_url, payment_id])

    def initiate_stk_push(self, **kwargs):
        """
        Initiates an stk push transaction

        Args:
          Required:
            transaction_amount  - Amount to request.
            phone_number        - Phone number of subscriber (Format: E.164).
            wallet_id - The default wallet id to use.

          Optional:
            transaction_id       - A unique transaction id
            service_reference_id - A means for a merchant to group related transactions  # noqa
            callback_url         -  URL on merchant side to post transaction status
            paybill - The paybill/till_number to use while initiating the trx.

        Example:
            initiate_stk_push(
                phone_number='254700000000',
                transaction_amount=200.00,
                wallet_id='871559E4-BED1-4E0C-A4B0-FBD2A5833E00',
                transaction_id='871559E4-BED1-4E0C-A4B0-FBD2A5833E00',
                callback_url='http://merchant.co.ke/callback/oc/trx/0xdeadbeef')
        """
        data = kwargs
        response = requests.post(
            self.stkpush_url,
            auth=self.auth, headers=self.headers, json=data)
        return self.process_response(
            response, schema.StkPushTransactionSchema())
