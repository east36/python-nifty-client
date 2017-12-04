import logging
from niftyclient import NiftyClient


class Config:
    key_id = ''
    secret = ''
    user_id = ''
    api_base = 'https://api.integ.nifty.co.ke/api/v1'


def mk_logger(level=logging.INFO):
    log_format = (
        '%(asctime)s - %(name)s - %(levelname)s - '
        '[%(filename)s:%(lineno)s %(funcName)s()] - %(message)s')
    logging.basicConfig(format=log_format, level=level)
    logger = logging.getLogger('wallet_example')
    return logger


def enumerate_wallets(client, logger):
    result = client.wallet.get_wallet()
    logger.info(
        (
            "[i] Viewing {result.returned_resultset_size} wallets "
            "out of {result.available_resultset_size}"
        ).format(result=result)
    )
    for wallet in result.wallets:
        logger.info(
            (
                " > Wallet: user={wallet.user_name}, "
                "balance={wallet.balance}"
            ).format(wallet=wallet)
        )
    logger.info("")


def enumerate_c2b_transactions(client, logger, **kwargs):
    result = client.c2b.list_transactions(**kwargs)
    logger.info(
        (
            "[i] Viewing {result.returned_resultset_size} transactions "
            "out of {result.available_resultset_size}"
        ).format(result=result)
    )
    for transaction in result.transactions:
        logger.info(
            (
                " > Transaction: phone_number={trx.phone_number}, "
                "id={trx.transaction_id} amount={trx.trans_amount}"
            ).format(trx=transaction))
    logger.info("")


def enumerate_online_checkout_transactions(client, logger, **kwargs):
    result = client.online_checkout.list_transactions(**kwargs)
    logger.info(
        (
            "[i] Viewing {result.returned_resultset_size} "
            "transactions out of {result.available_resultset_size}"
        ).format(result=result)
    )
    for transaction in result.transactions:
        logger.info(
            (
                " > Transaction: phone_number={trx.phone_number}, "
                "payment_id={trx.payment_id}, status={trx.status}"
            ).format(trx=transaction))
    logger.info("")


if __name__ == '__main__':
    logger = mk_logger()
    client = NiftyClient(Config(), logger)

    # Wallets:
    # Create wallet
    print client.wallet.create_wallet()
    logger.info("")
    enumerate_wallets(client, logger)

    # Claim a token. Send a minimal amount (10 Shillings) to paybill 291222
    response = client.c2b.claim_transaction(
        transaction_id='LGN1NLQ4QV', till_number="291222",
        phone_number="25471123456"
    )
    if response.transactions:
        transaction = response.transactions[0]
        logger.info(
            ("Success in claiming: trx_id: {trx.transaction_id} "
             "of value {trx.trans_amount}").format(trx=transaction)
        )

    # List all transactions
    enumerate_c2b_transactions(client, logger)

    # Or search for a specific phone number
    enumerate_c2b_transactions(client, logger, phone_number='25471123456')

    # Or search for  a specific phone number using limit and offset
    enumerate_c2b_transactions(
        client, logger, phone_number='25471123456', limit=1, offset=2)

    # Get a transaction using payment_id
    response = client.c2b.get_transaction(
        "2125c3f6-680d-11e7-a87a-063d7358ef43")
    if response.transactions:
        transaction = response.transactions[0]
        logger.info(
            ("Fetched Transaction: trx_id: {trx.transaction_id} "
             "of value {trx.trans_amount}").format(trx=transaction)
        )

    # Reverse transaction
    response = client.c2b.list_transactions()
    sample_transaction = response['transactions'][0]
    payment_id = sample_transaction['payment_id']
    logger.info("Reversal of %s: %s" % (
        payment_id,
        client.c2b.reverse_transaction(
            payment_id=str(payment_id),
            reversal_reason="customer initiated")
        )
    )

    # Online Checkout
    # Iniate an online checkout
    result = client.online_checkout.initiate_checkout(
        phone_number='25471123456', transaction_amount=10,
        service_reference_id="python-test")
    if result and result.transactions:
        print (
            "#{trx.payment_id}> Requested #{trx.transaction_amount}"
            " from #{trx.phone_number}").format(trx=result.transactions[0])
    enumerate_online_checkout_transactions(client, logger, limit=1, offset=2)
