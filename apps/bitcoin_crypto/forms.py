from django import forms
from decimal import Decimal

from apps.bitcoin_crypto.models import Transaction, OrderBook, SGDWallet, MinimunCoin, ConfirmFiatTransaction, ConfirmCrytpoRequest, OrderCoverTransaction, MarketLimit, DisputeUpload
from apps.bitcoin_crypto.utils import create_connection, get_balance #get_btc_balance,
from apps.fees.utils import get_transaction_fee
from django.utils.translation import ugettext_lazy as _
from forex_python.bitcoin import BtcConverter
from django.contrib.sites.models import Site

from request_middleware.middleware import get_request

class TransactionForm(forms.Form):
    """
        form validation for bitcoin withdrawal
    """
    address = forms.CharField(max_length=35)
    amount = forms.DecimalField(decimal_places=8)

    def clean_address(self):
        address = self.cleaned_data["address"]
        
        access = create_connection()
        valid = access.validateaddress(str(address))

        if not valid['isvalid']:
             raise forms.ValidationError("Invalid bitcoin address")

        return address

    def clean_amount(self):
        minimum_value = round(Decimal(.00000547), 8)
        amount = self.cleaned_data["amount"]

        r = get_request()

        balance = get_balance(self.user , r.session['base_pair'])
        transaction_fee = get_transaction_fee(amount, r.session['base_pair'], 'withdrawal')
        if amount < minimum_value:
             raise forms.ValidationError("The minimum amount you can withdraw is {}".format(minimum_value))
        elif balance < (amount+transaction_fee):
             raise forms.ValidationError("Amount is greater than wallet balance.")

        return amount

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')

        super().__init__(*args, **kwargs)


class VaultTransactionForm(forms.Form):
    """
        form validation for bitcoin withdrawal
    """
    address = forms.CharField(max_length=34)
    amount = forms.DecimalField(decimal_places=8, min_value=round(Decimal(.00000547),8))

    def clean_address(self):
        address = self.cleaned_data["address"]

        valid = self.access.validateaddress(str(address))

        if not valid['isvalid']:
             raise forms.ValidationError("Invalid bitcoin address")

        return address

    def clean_amount(self):
        amount = self.cleaned_data["amount"]

        account_balance = self.access.getbalance()
        btc_limit_obj, create = MinimunCoin.objects.get_or_create(site=Site.objects.get_current())
        minimum_limit = Decimal(btc_limit_obj.btc_limit)

        if (account_balance - amount) < minimum_limit:
             raise forms.ValidationError("The amount entered will cause the balance to go below minimum limit.")

        return amount

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.access = create_connection()

        super().__init__(*args, **kwargs)

class ConfirmFiatTransactionForm(forms.ModelForm):
    class Meta:
        model = ConfirmFiatTransaction
        fields = ["amount", "fiat_type", "receive_address", "is_confirm", "is_cancel", "crypto_amount", "crypto_type", "order", "sender", "receiver", "pending_order"]

class ConfirmCrytpoRequestForm(forms.ModelForm):
    class Meta:
        model = ConfirmCrytpoRequest
        fields = ["amount", "fiat_type", "is_confirm", "is_cancel", "crypto_amount", "crypto_type", "order", "sender", "receiver"]

class OrderCoverTransactionForm(forms.ModelForm):
    class Meta:
        model = OrderCoverTransaction
        fields = ["amount", "user", "order"]

class ExchangeForm(forms.ModelForm):
    """
        form to place sell orders and buy orders of different type
    """
    total = forms.FloatField()
    class Meta:
        model = OrderBook
        exclude = ('coins_covered', 'trade_status', 'order_time', 'trading_fee', 'canceled', 'maker')

    def clean(self):
        data = self.cleaned_data
        user = data['user']
        amount = data['amount']
        price = data['price']
        order_type = data['order_type']
        order_mode = data['order_mode']
        is_otc = data['is_otc']
        print(is_otc, data['is_otc'], "----------------------")
        if amount <= 0:
            raise forms.ValidationError(_("Amount should be greater than zero"))
        if price <= 0:
            raise forms.ValidationError(_("Price should be greater than zero"))

        if order_type == '0':
            # try:
            #     available_sgd_amount = SGDWallet.objects.get(user=user).amount
            # except:
            #     available_sgd_amount = 0.0


            r = get_request()
            if r.session['is_otc'] == 0:
                available_to_amount = get_balance(user, r.session['to_pair'])
                buy_volume = float(price) * float(amount)
                if buy_volume > available_to_amount:
                    raise forms.ValidationError(_("You don't have sufficient balance in your account."))

            if order_mode == '2':
                stop = data['limit']
                if price < stop:
                    raise forms.ValidationError(_("Stop value can not be greater than price"))

        else:
            r = get_request()
            available_base_amount = get_balance(user, r.session['base_pair'])
            market_limit_obj, create = MarketLimit.objects.get_or_create()
            if market_limit_obj.min_price_limit and market_limit_obj.max_price_limit and market_limit_obj.min_amount_limit and market_limit_obj.max_amount_limit:
                min_price_limit = float(market_limit_obj.min_price_limit)
                max_price_limit = float(market_limit_obj.max_price_limit)
                min_amount_limit = float(market_limit_obj.min_amount_limit)
                max_amount_limit = float(market_limit_obj.max_amount_limit)
                if amount < min_amount_limit or amount > max_amount_limit:
                    raise forms.ValidationError(_("Order Amount is out of limit: " + str(min_amount_limit) + "~" + str(max_amount_limit)))
                if price < min_price_limit or price > max_price_limit:
                    raise forms.ValidationError(_("Order Price is out of limit: " + str(min_price_limit)  + "~" + str(max_price_limit)))
            print("this is market limit", market_limit_obj);
            if available_base_amount < amount:
                raise forms.ValidationError(_("You don't have sufficient in your wallet."))
                # available_to_amount = get_balance(user, r.session['to_pair'])
                # if available_to_amount < amount:
                #     raise forms.ValidationError(_("You don't have sufficient in your wallet."))
            # b = BtcConverter()
            # sell_volume = float(price) * float(amount)
            # available_btc_amount_in_sgd = b.convert_to_btc(sell_volume, 'SGD')
            # if available_btc_amount_in_sgd > available_btc_amount:
            #     raise forms.ValidationError(_("You don't have sufficient balance in your account."))

            if order_mode == '2':
                stop = data['limit']
                if price > stop:
                    raise forms.ValidationError(_("Stop value can not be less than price"))

        return data


class ReportForm(forms.Form):
    fromdate = forms.DateField(input_formats=['%Y-%m-%d'])
    todate = forms.DateField(input_formats=['%Y-%m-%d'])

    def clean(self):
        data = self.cleaned_data
        print(data)
        fromdate = data['fromdate']
        todate = data['todate']

        if fromdate > todate:
            raise forms.ValidationError(_("To date is less than From date"))

        return data


class AddSGDForm(forms.Form):
    """
        validation of sgd amount
    """
    amount = forms.DecimalField(decimal_places=2)

    def clean_amount(self):
        amount = self.cleaned_data["amount"]
        
        if amount <= Decimal(0):
            raise forms.ValidationError("Value should be greater than zero")

        return amount

class DisputeUploadForm(forms.ModelForm):

    class Meta:
        model = DisputeUpload
        fields = ['front_page', 'description', 'client_phonenumber', 'user_phonenumber', 'user_email', 'dispute_status']

        error_messages = {
            'front_page': {
                'required': _("Front Page is required"),
            },
            'description': {
                'required': _("Description is required"),
            },
            'client_phonenumber': {
                'required': _("Client Phone number is required"),
            },
            'user_phonenumber': {
                'required': _("User Phone number is required"),
            },
            'user_email': {
                'required': _("User Email is required"),
            },
        }

    def __init__(self, *args, **kwargs):
        super(DisputeUploadForm, self).__init__(*args, **kwargs)
        self.fields["front_page"].required = True
        self.fields["description"].required = True
        self.fields["client_phonenumber"].required = True
        self.fields["user_phonenumber"].required = True
        self.fields["user_email"].required = True