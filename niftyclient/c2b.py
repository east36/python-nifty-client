import requests
from . import schema
from .client_base import ClientBase


class C2B(ClientBase):

    @property
    def c2b_url(self):
        return '{self.user_url}/mpesa/c2b-confirmation'.format(self=self)

    def get_c2b_transaction_url(self, payment_id):
        return "/".join([self.c2b_url, payment_id])

    def claim_transaction(self, **kwargs):
        """
        Claim a transaction using a token and credit wallet with token amount.

        Args (All required):
            transaction_id - MPESA transaction id sent to the subscriber.
            phone_number   - Phone number of the subscriber (Format: E.164).
            till_number    - Short code that transaction was sent to.

        Example:
            claim_transaction(transaction_id='LX128323',
                              phone_number='25470000000', till_number='291222')
        """
        data = kwargs
        response = requests.post(
            self.c2b_url, auth=self.auth, headers=self.headers, json=data)
        return self.process_response(response, schema.C2BTransactionSchema())

    def list_transactions(self, **kwargs):
        """
        List or search C2B Transactions
        Args (All optional):
            transaction_id - MPESA transaction id to look up.
            phone_number   - Phone number to look up (Format: E.164).
            till_number    - Short code to look up.

        Example:
            list_transactions()
            list_transactions(transaction_id='LX128323',
                              phone_number='25470000000', till_number='291222')

        """
        data = kwargs
        response = requests.get(
            self.c2b_url, auth=self.auth, headers=self.headers, params=data)
        return self.process_response(response, schema.C2BTransactionSchema())

    def get_transaction(self, payment_id):
        """
        Get a transaction using a payment id.__lt__(
        Args (Required):
            payment_id     - Transaction payment ID

        Example:
            get_transactions('DFE825EF-15EA-458E-9E8D-D3C9CC080BC3')
        """
        response = requests.get(
            self.get_c2b_transaction_url(payment_id),
            auth=self.auth, headers=self.headers)
        return self.process_response(response, schema.C2BTransactionSchema())

    def reverse_transaction(self, **kwargs):
        """
        Reverse a transaction and debit wallet with token amount.
        This will initiate an MPESA reversal process.

        Args (All required):
            payment_id     - Payment ID of the transaction to reverse

        Example:
            reverse_transaction(
                payment_id='54FC0F32-4533-47FA-9894-9BE2271CAB3F')
        """
        data = kwargs
        response = requests.put(
            self.get_c2b_transaction_url(data.pop('payment_id')),
            auth=self.auth, headers=self.headers, json=data)
        return self.process_response(response, schema.C2BTransactionSchema())
