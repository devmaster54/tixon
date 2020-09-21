import os
import hashlib
import hmac
import json
import requests
import subprocess
import datetime


from bitcoin import *
from decimal import Decimal
from django.db.models import Sum, F, Q
from django.shortcuts import get_object_or_404
from pywallet import wallet
from bitcoinrpc.authproxy import AuthServiceProxy

from apps.bitcoin_crypto.models import WalletAddress, Wallet, Transaction, VaultWallet,\
 VaultTransaction, WatchOnlyAddress, OrderBook, SGDWallet, OrderMatchingHistory, ConfirmFiatTransaction, OrderCoverTransaction
from apps.fees.models import TransactionFee
from request_middleware.middleware import get_request

CHANGELLY_API_URL = 'https://api.changelly.com'

CHANGELLY_API_KEY = os.environ.get('TWILIO_ACCOUNT_SID')
CHANGELLY_API_SECRET = os.environ.get('TWILIO_ACCOUNT_SID')
BLOCKCIPHER_API_KEY = os.environ.get('TWILIO_ACCOUNT_SID')

def changelly_transaction(method, params):
    message = {
                  "jsonrpc": "2.0",
                  "method": method,
                  "params": params,
                  "id": 1
                }

    serialized_data = json.dumps(message)

    sign = hmac.new(CHANGELLY_API_SECRET.encode('utf-8'), serialized_data.encode('utf-8'), hashlib.sha512).hexdigest()

    headers = {'api-key': CHANGELLY_API_KEY, 'sign': sign, 'Content-type': 'application/json'}
    response = requests.post(API_URL, headers=headers, data=serialized_data)

    return response.json()

def create_connection():
    r = get_request()
    if r.session['base_pair'] == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
        return access
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
        return access

def create_btc_wallet(user):
    access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
    addr = access.getnewaddress(user.username)
    wallet, created = Wallet.objects.get_or_create(user=user, name='BTC')
    wallet.addresses.add(WalletAddress.objects.create(address=addr))
    return addr

def create_txch_wallet(user):
    access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
    addr = access.getnewaddress(user.username)
    wallet, created = Wallet.objects.get_or_create(user=user, name='TXCH')
    wallet.addresses.add(WalletAddress.objects.create(address=addr))
    return addr

# def get_btc_balance(user):
#     access = create_connection()
#     balance = Decimal(access.getreceivedbylabel(user.username))
#     transaction = Transaction.objects.filter(user=user, currency="btc", transaction_type='withdrawal', invalid=False, pending=False, rejected=False)

#     if transaction:
#         txn_fee = sum([ txn.transaction_fee_except_mining_fees() for txn in transaction]) + Decimal(transaction.aggregate(Sum('mining_fee'))['mining_fee__sum'])
#         balance = balance - (sum([Decimal(obj.amount) for obj in transaction]) + txn_fee)

#     sell_orders = OrderBook.objects.filter(user=user, order_type=1, canceled=False)
#     cancelled_sell_orders = OrderBook.objects.filter(user=user, order_type=1, canceled=True)

#     if sell_orders.exists():
#         balance = balance - Decimal(sell_orders.aggregate(Sum('amount'))['amount__sum'])

#     if cancelled_sell_orders.exists():
#           balance = balance - Decimal(sell_orders.aggregate(Sum('coins_covered'))['coins_covered__sum'])

#     # buy_orders = OrderBook.objects.filter(user=user, order_type=0)
#     # if buy_orders.exists():
#     #     balance = balance + Decimal(buy_orders.aggregate(Sum('coins_covered'))['coins_covered__sum'])

#     return balance

def get_account_name(address, currency):
    if currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
    
    account_name = access.getaccount(address)
    if account_name:
        return account_name
    return False

def transfer_coin(fromadress, toaddress, amount, currency):
    if currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
    try:
        from_one = access.getaccount(fromadress)
        to_one = access.getaccount(toaddress)
    except:
        return False
    if from_one and to_one:
        balance = get_balancenew(from_one, currency)
        if balance > Decimal(amount):
            valid = access.move(from_one, to_one, Decimal(amount))
            return valid
        return False
    return False

def get_balancenew(username, currency):
    if currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
        balance = Decimal(access.getreceivedbylabel(username))
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
        balance = access.getbalance(username)
    return round(balance,8)

def get_balance(user, currency):
    if currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
        balance = Decimal(access.getreceivedbylabel(user.username))
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
        balance = access.getbalance(user.username)
    # transaction = Transaction.objects.filter(user__username=user.username,currency=currency, transaction_type='withdrawal', invalid=False, pending=False, rejected=False)
    r = get_request()
    #order_type = 0 :buy, 1 :sell
    # Covered Session
    #========================OTC===================================
    covered_amount_from_otc =  ConfirmFiatTransaction.objects.filter(is_confirm=1, crypto_type=currency.upper(), sender__email=user).aggregate(Sum('crypto_amount'))["crypto_amount__sum"]
    if not covered_amount_from_otc:
        covered_amount_from_otc = 0
    covered_amount_from_otc1 =  ConfirmFiatTransaction.objects.filter(is_confirm=1, crypto_type=currency.upper(), receiver__email=user, order__order_type=0).aggregate(Sum('crypto_amount'))["crypto_amount__sum"]
    if not covered_amount_from_otc1: #sent amount for fiat
        covered_amount_from_otc1 = 0
    covered_amount_from_otc -= covered_amount_from_otc1

    #==================CTC=========================================
    passive_covered_amount_from_ctc11 = OrderCoverTransaction.objects.filter(user__email=user, order__exchange_to=currency.upper(), order__order_type=1).aggregate(total=Sum(F('amount')*F('order__price')))["total"]
    if not passive_covered_amount_from_ctc11: #confirmed bid on other's sell orders
        passive_covered_amount_from_ctc11 = 0
    covered_amount_from_otc -= passive_covered_amount_from_ctc11

    passive_covered_amount_from_ctc2 = OrderCoverTransaction.objects.filter(user__email=user, order__exchange_form=currency.upper(), order__order_type=1).aggregate(Sum('amount'))["amount__sum"]
    if not passive_covered_amount_from_ctc2:    #confirmed bid on other's buy orders
        passive_covered_amount_from_ctc2 = 0
    covered_amount_from_otc += passive_covered_amount_from_ctc2 

    passive_covered_amount_from_ctc21 = OrderCoverTransaction.objects.filter(user__email=user, order__exchange_to=currency.upper(), order__order_type=0).aggregate(Sum('amount'))["amount__sum"]
    if not passive_covered_amount_from_ctc21:    #covers_amount to other's buy orders -
        passive_covered_amount_from_ctc21 = 0
    covered_amount_from_otc -= passive_covered_amount_from_ctc21

    passive_covered_amount_from_ctc22 = OrderCoverTransaction.objects.filter(user__email=user, order__exchange_form=currency.upper(), order__order_type=0).aggregate(total=Sum(F('amount')*F('order__price')))["total"]
    if not passive_covered_amount_from_ctc22:    #covers_amount from other's buy orders +
        passive_covered_amount_from_ctc22 = 0
    covered_amount_from_otc += passive_covered_amount_from_ctc22

    active_covered_amount_from_ctc1 = OrderBook.objects.filter(exchange_to=currency.upper(), user__email=user, is_otc='0', order_type=0).aggregate(total=Sum('coins_covered'))["total"]
    active_covered_amount_from_ctc2 = OrderBook.objects.filter(exchange_to=currency.upper(), user__email=user, is_otc='0', order_type=1).aggregate(total=Sum(F('coins_covered')*F('price')))["total"]
    if not active_covered_amount_from_ctc1: #covered amount from my active buy order +
        active_covered_amount_from_ctc1 = 0
    if not active_covered_amount_from_ctc2: #covered amount from my active sell order + 
        active_covered_amount_from_ctc2 = 0
    covered_amount_from_otc += active_covered_amount_from_ctc1
    covered_amount_from_otc += active_covered_amount_from_ctc2

    
    # Order Session
    # =============== OTC part ===========================
    order_amount_from_otc = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='1').aggregate(Sum('amount'))["amount__sum"]
    if not order_amount_from_otc: #order amount from my active OTC order -
        order_amount_from_otc = 0
    canceled_order_amount_from_otc1 = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='1', order_type=1, canceled=1).aggregate(total=Sum(F('amount')-F('coins_covered')))["total"]
    if not canceled_order_amount_from_otc1: #order amount from canceld order
        canceled_order_amount_from_otc1 = 0
    covered_amount_from_otc += canceled_order_amount_from_otc1

    # =============== CTC part ===========================
    canceled_order_amount_from_ctc1 = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='0', order_type=1, canceled=1).aggregate(total=Sum(F('amount')-F('coins_covered')))["total"]
    if not canceled_order_amount_from_ctc1: #order amount from canceld order
        canceled_order_amount_from_ctc1 = 0
    covered_amount_from_otc += canceled_order_amount_from_ctc1
    canceled_order_amount_from_ctc2 = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='0', order_type=0, canceled=1).aggregate(total=Sum((F('amount')-F('coins_covered'))*F('price')))["total"]
    if not canceled_order_amount_from_ctc2: #order amount from canceld order
        canceled_order_amount_from_ctc2 = 0
    covered_amount_from_otc += canceled_order_amount_from_ctc2

    order_amount_from_ctc1 = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='0', order_type=0).aggregate(total=Sum(F('amount')*F('price')))["total"]
    order_amount_from_ctc2 = OrderBook.objects.filter(exchange_form=currency.upper(), user__email=user, is_otc='0', order_type=1).aggregate(Sum('amount'))["amount__sum"]
    if not order_amount_from_ctc1: #order amount from my buy active ctc order -
        order_amount_from_ctc1 = 0
    if not order_amount_from_ctc2: #order amount from my sell active ctc order -
        order_amount_from_ctc2 = 0
    order_amount_from_otc = order_amount_from_otc + order_amount_from_ctc1 + order_amount_from_ctc2
    # print(balance, covered_amount_from_otc,covered_amount_from_ctc,order_amount_from_otc,order_amount_from_ctc1,order_amount_from_otc,order_amount_from_ctc2)
    covered_amount = covered_amount_from_otc - order_amount_from_otc
    # print(covered_amount, covered_amount_from_otc, order_amount_from_otc, )

    TWOPLACES = Decimal(100) ** -3
    balance = balance + Decimal(covered_amount).quantize(TWOPLACES)

    # ========================== This is recently blocked by adding new move function =================== 2019/5/25

    # if transaction:
    #     txn_fee = sum([ txn.transaction_fee_except_mining_fees() for txn in transaction]) + Decimal(transaction.aggregate(Sum('mining_fee'))['mining_fee__sum'])
    #     balance = balance - (sum([Decimal(obj.amount) for obj in transaction]) + txn_fee)

    # sell_orders = OrderBook.objects.filter(user=user, order_type=1, canceled=False)
    # cancelled_sell_orders = OrderBook.objects.filter(user=user, order_type=1, canceled=True)

    # if sell_orders.exists():
    #     balance = balance - Decimal(sell_orders.aggregate(Sum('amount'))['amount__sum'])

    # if cancelled_sell_orders.exists():
    #       balance = balance - Decimal(sell_orders.aggregate(Sum('coins_covered'))['coins_covered__sum'])

    # buy_orders = OrderBook.objects.filter(user=user, order_type=0)
    # if buy_orders.exists():
    #     balance = balance + Decimal(buy_orders.aggregate(Sum('coins_covered'))['coins_covered__sum'])

    return round(balance,5)

def get_fee_balance():
    access = create_connection()
    balance = access.getreceivedbylabel('transaction fee collector')
    transaction = Transaction.objects.filter(transaction_type="fee_withdrawal", invalid=False, pending=False, rejected=False)

    if transaction:
        txn_fee = Decimal(transaction.aggregate(Sum('mining_fee'))['mining_fee__sum'])
        balance = balance - (sum([Decimal(obj.amount) for obj in transaction]) + txn_fee)

    return round(balance,8) 


def get_vault_balance(username, currency):
    access = create_connection()
    balance = access.getreceivedbylabel(username)
    transaction = VaultTransaction.objects.filter(user=username, currency=currency)
    if transaction:
        balance = balance - sum([Decimal(obj.amount) for obj in transaction])

    return balance


def get_account_balance(currency):
    if currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
    balance = access.getbalance()

    return balance


def create_vault_wallet(user, username, currency):
    access = create_connection()
    addr = access.getnewaddress(username)
    wallet, created = VaultWallet.objects.get_or_create(user=user, username=username, name=currency)
    wallet.addresses.add(WalletAddress.objects.create(address=addr))
    return addr

def total_pending_transaction_amount():
    transactions = Transaction.objects.filter(pending=True)
    
    amount = Decimal('0')
    for transaction in transactions:
        amount += Decimal(transaction.amount)

    return amount


def complete_pending_transaction(transaction):
    if transaction.currency == 'BTC':
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.176.17:9999")
    else :
        access = AuthServiceProxy("http://tixoner:123456789tixon@68.183.185.230:9988")
    # access = create_connection()
    balance = access.getbalance()
    from_balance = get_balance(transaction.user, 'TXCH')
    # print("action in withdrawl================================", balance)
    try:
        amount = Decimal(transaction.amount)
    except:
        amount = Decimal(0)
    
    transaction_fee = Decimal(transaction.transaction_fee)

    # getaccountaddress will be depricated in later version of bitcoin
    transaction_fee_to = access.getnewaddress("transfaction fee collector")

    # if balance >= (amount+transaction_fee) and from_balance >= (amount+transaction_fee):
    if from_balance >= (amount+transaction_fee):
        to_account = access.getaccount(transaction.transaction_to)
        # print(to_account, "===========this is to account")
        if to_account:
            valid = access.move(transaction.user.username, to_account, amount)
            if valid:
                transaction.pending = False
                transaction.transaction_id = 'move'
                # rpc_tansaction = access.gettransaction(valid)
                mining_fee = 0
                transaction.mining_fee = str(abs(mining_fee))
                # transaction.date = datetime.datetime.fromtimestamp(float(rpc_tansaction['time']))
                transaction.date = datetime.datetime.now().time()
                transaction.save()

                return True
            else:
                transaction.invalid = True
                transaction.save()
                return 'Invalid Transaction'
        else :
            if transaction_fee > Decimal(0):
                valid = access.sendmany(transaction.user.username,{transaction.transaction_to: amount, transaction_fee_to : transaction_fee}, 
                6,"",[transaction_fee_to])
            else:
                valid = access.sendtoaddress(transaction.transaction_to, amount)

            if valid:
                transaction.pending = False
                transaction.transaction_id = valid
                rpc_tansaction = access.gettransaction(valid)
                mining_fee = rpc_tansaction['fee']
                transaction.mining_fee = str(abs(mining_fee))
                transaction.date = datetime.datetime.fromtimestamp(float(rpc_tansaction['time']))
                transaction.save()

                return True
            else:
                transaction.invalid = True
                transaction.save()
                return 'Invalid Transaction'
            
    return 'Please Maintain Main Wallet Amount to Complete this Transaction.'


def recived_by_address(address):
    access = create_connection()
    amount = access.getreceivedbyaddress(address)
    if amount == Decimal('0E-8'):
        return Decimal('0.00')
    return amount


def checkwatchonlyaddress():
    access = create_connection()
    vault_list = WatchOnlyAddress.objects.all()
    for obj in vault_list:
        if not access.validateaddress(obj.address)['iswatchonly']:
            obj.delete()


def get_publict_key(vault_address):
    access = create_connection()
    vault_list = WatchOnlyAddress.objects.all()
    for obj in vault_list:
        try:
            prv_key = access.dumpprivkey(obj.address)
            if prv_key == vault_address:
                return obj.address
        except:
            pass

    return 'non vault address'


def get_transaction_fee(amount, currency, fee_type):
    """return transction fee of parameters amount, currecny, fee type"""

    # checking any transaction fee object exist else return fees to zero

    try:
        transaction_fee_obj = get_object_or_404(TransactionFee, currency=currency, fee_type=fee_type)
    except:
        return Decimal(0)

    fee_limits = transaction_fee_obj.transactionfeerange_set.all()

    #identifing fee range object of amount
    fee_obj = None
    for fee_limit in fee_limits:
        if Decimal(fee_limit.value) <= Decimal(amount):
            if fee_obj:
                fee_obj = fee_limit if Decimal(fee_obj.value) <  Decimal(fee_limit.value) else fee_obj
            else:
                fee_obj = fee_limit

    #calculating transaction fees according to rate type
    if not fee_obj:
        return Decimal(0)
        
    if transaction_fee_obj.rate_type == 'percentage':
        fee = Decimal(amount) * Decimal(fee_obj.fees)/100
    else:
        fee =  Decimal(fee_obj.fees)

    return fee


def complete_order(request, order_instance):
    
    if order_instance.order_type == '0':
        order_instance.save()
        # #processing buy order
        # if order_instance.order_mode == '0':
        #     # market order
        #     sell_orders = OrderBook.objects.filter(order_type='1', trade_status=False).order_by('price','id')
        # elif order_instance.order_mode == '1':
        #     #limit order
        #     sell_orders = OrderBook.objects.filter(order_type='1', trade_status=False, price__lte=order_instance.price).order_by('price','id')
        #     print("-----sell orders----------", sell_orders);            
        # elif order_instance.order_mode == '2':
        #     #stop-limit order
        #     limit = order_instance.limit
        #     sell_orders = OrderBook.objects.filter(order_type='1', trade_status=False, price__lte=order_instance.price,
        #         price__gte=limit).order_by('price','id')
        # print("-----sell orders----------", sell_orders);
        # completed_amount = 0.0
        # remining_amount = order_instance.amount
        # orders_to_process = []
        # total_price = 0.0

        # for sell_order in sell_orders:

        #     sell_order_amount = sell_order.amount - sell_order.coins_covered

        #     if remining_amount == sell_order_amount:
        #         completed_amount += remining_amount
        #         total_price += sell_order.price * remining_amount
        #         remining_amount = 0.0
        #         orders_to_process.append((sell_order, sell_order_amount))
        #         break
        #     elif remining_amount > sell_order_amount:
        #         completed_amount += sell_order_amount
        #         total_price += sell_order.price  * sell_order_amount
        #         remining_amount -= sell_order_amount
        #         orders_to_process.append((sell_order, sell_order_amount))
        #     else:
        #         completed_amount += remining_amount
        #         total_price += sell_order.price * remining_amount
        #         orders_to_process.append((sell_order, remining_amount))
        #         remining_amount = 0.0
        #         break

        # transaction_fee = get_transaction_fee(total_price, 'sgd', 'taker')

        # sgdwallet, create = SGDWallet.objects.get_or_create(user=order_instance.user)
        # current_balance = sgdwallet.amount

        # if total_price + float(transaction_fee) + remining_amount * order_instance.price > current_balance:
        #     return False

        # access = create_connection()
        # for order_to_process_tuple in orders_to_process:
        #     access.move(order_to_process_tuple[0].user.username, order_instance.user.username, order_to_process_tuple[1])

        #     sgdwallet, create = SGDWallet.objects.get_or_create(user=order_instance.user)
        #     new_balance = sgdwallet.amount + order_to_process_tuple[1] * order_to_process_tuple[0].price
        #     SGDWallet.objects.filter(user=order_to_process_tuple[0].user).update(amount=new_balance)

        #     if (order_to_process_tuple[0].amount - order_to_process_tuple[0].coins_covered) ==\
        #      order_to_process_tuple[1]:
        #         order_to_process_tuple[0].trade_status = True

        #     order_to_process_tuple[0].coins_covered += order_to_process_tuple[1]
        #     order_to_process_tuple[0].save()

        # order_instance.coins_covered += completed_amount
        # order_instance.trading_fee += float(transaction_fee)
        # if remining_amount == 0.0:
        #     order_instance.trade_status = True
        # else:
        #     order_instance.maker = True

        # order_instance.save()

        # for order_to_process_tuple in orders_to_process:
        #     OrderMatchingHistory(processing_order=order_instance, matched_order=order_to_process_tuple[0],
        #         coins_covered=order_to_process_tuple[1], matching_price=order_to_process_tuple[0].price,
        #         trading_fee=transaction_fee).save()
            
        # balance_amount = current_balance - (total_price + float(transaction_fee) + remining_amount * order_instance.price)
        # SGDWallet.objects.filter(user=order_instance.user).update(amount=balance_amount)

        return True

    if order_instance.order_type == '1':
         ##processing buy order
        # if order_instance.order_mode == '0':
        #     # market order
        #     buy_orders = OrderBook.objects.filter(order_type='0', trade_status=False).order_by('-price','id')
        # elif order_instance.order_mode == '1':
        #     #limit order
        #     buy_orders = OrderBook.objects.filter(order_type='0', trade_status=False, price__gte=order_instance.price).order_by('-price','id')
        # elif order_instance.order_mode == '2':
        #     #stop-limit order
        #     limit = order_instance.limit
        #     buy_orders = OrderBook.objects.filter(order_type='0', trade_status=False, price__gte=order_instance.price,
        #         price__lte=limit).order_by('-price','id')

        # completed_amount = 0.0
        # remining_amount = order_instance.amount
        # orders_to_process = []
        # total_price = 0.0

        # for buy_order in buy_orders:

        #     buy_order_amount = buy_order.amount - buy_order.coins_covered

        #     if remining_amount == buy_order_amount:
        #         completed_amount += remining_amount
        #         total_price += buy_order.price * remining_amount
        #         remining_amount = 0.0
        #         orders_to_process.append((buy_order, buy_order_amount))
        #         break
        #     elif remining_amount > buy_order_amount:
        #         completed_amount += buy_order_amount
        #         total_price += buy_order.price  * buy_order_amount
        #         remining_amount -= buy_order_amount
        #         orders_to_process.append((buy_order, buy_order_amount))
        #     else:
        #         completed_amount += remining_amount
        #         total_price += buy_order.price * remining_amount
        #         orders_to_process.append((buy_order, remining_amount))
        #         remining_amount = 0.0
        #         break

        # transaction_fee = get_transaction_fee(total_price, 'sgd', 'taker')

        # sgdwallet, create = SGDWallet.objects.get_or_create(user=order_instance.user)
        # current_balance = sgdwallet.amount

        # if  float(transaction_fee) > current_balance + total_price:
        #     return False

        # access = create_connection()
        # for order_to_process_tuple in orders_to_process:
        #     access.move(order_instance.user.username, order_to_process_tuple[0].user.username, order_to_process_tuple[1])

        #     if (order_to_process_tuple[0].amount - order_to_process_tuple[0].coins_covered) ==\
        #      order_to_process_tuple[1]:
        #         order_to_process_tuple[0].trade_status = True

        #     order_to_process_tuple[0].coins_covered += order_to_process_tuple[1]
        #     order_to_process_tuple[0].save()

        # order_instance.coins_covered += completed_amount
        # order_instance.trading_fee += float(transaction_fee)
        # if remining_amount == 0.0:
        #     order_instance.trade_status = True
        # else:
        #     order_instance.maker = True

        # order_instance.save()

        # for order_to_process_tuple in orders_to_process:
        #     OrderMatchingHistory(processing_order=order_instance, matched_order=order_to_process_tuple[0],
        #         coins_covered=order_to_process_tuple[1], matching_price=order_to_process_tuple[0].price,
        #         trading_fee=transaction_fee).save()

        # balance_amount = current_balance + total_price
        # SGDWallet.objects.filter(user=order_instance.user).update(amount=balance_amount)

        return True


def calculate_24Hr_time():
    current = datetime.datetime.now()
    hr24_before = current - datetime.timedelta(hours=24)
    return current, hr24_before