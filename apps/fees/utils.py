from decimal import Decimal
from django.shortcuts import get_object_or_404

from apps.bitcoin_crypto.utils import create_connection

from .models import TransactionFee


def set_mining_fees(mining_fees):
    access = create_connection()

    try:
        access.settxfee(mining_fees)
        return True
    except:
        return False


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


