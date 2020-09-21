import json
import requests
import pytz

import datetime
from django import template
from django.db.models import Q, Max, Min, Avg

from apps.bitcoin_crypto.utils import *
from apps.bitcoin_crypto.models import MinimunCoin, SGDWallet, OrderMatchingHistory, ConfirmFiatTransaction
from django.contrib.sites.models import Site
from forex_python.bitcoin import BtcConverter
from apps.authentication.models import User
from django.utils import timezone
from decimal import *

from request_middleware.middleware import get_request

register = template.Library()

@register.simple_tag
def transaction_status(trans_id):
    params = {"id": trans_id}
     
    data = changelly_transaction('getStatus', params)
    if data.get('error'):
        return "Payment not received.Failed."
    else:
        return data.get('result')

@register.simple_tag
def get_crypto_balance(user):
    try:
        user.username
    except:
        return 0
    r = get_request()
    balance = get_balance(user, r.session['base_pair'])
    if not balance:
        balance = 0
    return balance    

@register.simple_tag
def get_crypto_balance_new(user):
    try:
        user.username
    except:
        return 0
    r = get_request()
    balance = get_balance(user, r.session['to_pair'])
    if not balance:
        balance = 0
    return balance 

@register.simple_tag
def get_balance_btc(user):

    try:
        user.username
    except:
        return 0
    r = get_request()
    balance = get_balance(user, 'BTC')
    if not balance:
        balance = 0
    return balance #+ Decimal(covered_amount).quantize(TWOPLACES)

@register.simple_tag
def get_balance_txch(user):

    try:
        user.username
    except:
        return 0
    balance = get_balance(user, 'TXCH')
    if not balance:
        balance = 0
    return balance #+ Decimal(covered_amount).quantize(TWOPLACES)

@register.simple_tag
def get_account_balance_btc():
    balance = get_account_balance('BTC')
    if not balance:
        balance = 0
    return balance

@register.simple_tag
def get_account_balance_txch():
    balance = get_account_balance('TXCH')
    if not balance:
        balance = 0
    return balance

@register.simple_tag
def conver_unix_to_datetime(unix_string):
    date_time_obj = datetime.datetime.fromtimestamp(float(unix_string))
    aware_time = timezone.make_aware(date_time_obj, timezone=pytz.timezone('UTC'))

    return timezone.localtime(aware_time).strftime('%m/%d/%Y %H:%M:%S')

@register.simple_tag
def get_transaction_details(transaction_id):
    access = create_connection()
    transaction_obj = access.gettransaction(transaction_id)
    return transaction_obj


@register.simple_tag
def get_transaction_date(transaction_id):
    access = create_connection()
    transaction_obj = access.gettransaction(transaction_id)
    date_time_obj = datetime.datetime.fromtimestamp(float(transaction_obj['time']))
    aware_time = timezone.make_aware(date_time_obj, timezone=pytz.timezone('UTC'))
    return timezone.localtime(aware_time).strftime('%m/%d/%Y %H:%M:%S')


@register.filter
def get_transaction_status(transaction_id):
    access = create_connection()
    transaction_obj = access.gettransaction(transaction_id)
    return transaction_obj['confirmations']


@register.simple_tag
def get_minimum_limit_btc():
    btc_limit_obj, create = MinimunCoin.objects.get_or_create(site=Site.objects.get_current())
    btc_limit = Decimal(btc_limit_obj.btc_limit)
    return btc_limit

@register.simple_tag
def get_pending_transaction_amount():
    return total_pending_transaction_amount()


@register.simple_tag
def get_amount_to_keep_minimu_limit():
    minimum_limit = get_minimum_limit_btc()
    current_wallet_balance = get_account_balance_btc()
    pending_transaction_amount = get_pending_transaction_amount()

    except_wallet_amount = minimum_limit + pending_transaction_amount

    if except_wallet_amount > current_wallet_balance:
        amount_to_add = except_wallet_amount - current_wallet_balance
    else:
        amount_to_add = Decimal('0')

    return amount_to_add


@register.simple_tag
def get_recived_by_address(address):
    return recived_by_address(address)


@register.simple_tag
def get_sgd_balance(user):
    try:
        balance = SGDWallet.objects.get(user=user).amount
        return round(balance, 3)
    except:
        return 0.0


@register.filter
def in_decimal(value):
    if '0E-8' == value:
        return '0.00'

    return value

@register.simple_tag
def btc_price_in_sgd():

    try:
        price =  OrderMatchingHistory.objects.all().latest('order_matching_time').matching_price
    except:
        price = 0.0

    return price

@register.simple_tag
def total_price(price, amount):
    total = price*amount
    return total

@register.simple_tag
def percentage_completed(received, amount):

    print(received/amount)
    try:
        percentage = round((received/amount)*100, 2)
    except:
        percentage = Decimal(0.00)
        
    return percentage


@register.simple_tag
def fee_balance():
    return get_fee_balance()


@register.simple_tag
def get_24Hr_high():
    current, hr24_before = calculate_24Hr_time()
    max_value = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Max('matching_price'))

    max_value = max_value.get('matching_price__max', 0) if max_value.get('matching_price__max', 0) else 0.0

    return max_value


@register.simple_tag
def get_24Hr_low():
    current, hr24_before = calculate_24Hr_time()
    min_value = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Min('matching_price'))
    min_value = min_value.get('matching_price__min', 0) if min_value.get('matching_price__min', 0) else 0.0
    return min_value


@register.simple_tag
def get_24Hr_change():
    current, hr24_before = calculate_24Hr_time()
    try:
        price_before_24hr = OrderMatchingHistory.objects.filter(order_matching_time__lte=hr24_before).latest('order_matching_time').matching_price
    except:
        price_before_24hr = 0.0
        
    try:
        current_price = OrderMatchingHistory.objects.filter(order_matching_time__lte=current).latest('order_matching_time').matching_price
    except:
        current_price = price_before_24hr
        
    return current_price - price_before_24hr



@register.simple_tag
def get_24Hr_sum():
    current, hr24_before = calculate_24Hr_time()
    price = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Sum('matching_price', field="matching_price * coins_covered"))
    price = price.get('matching_price__sum', 0) if price.get('matching_price__sum', 0) else 0.0
    return price