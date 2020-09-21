from django.db import models
from apps.authentication.models import User
from django.contrib.sites.models import Site
from decimal import Decimal


class WalletAddress(models.Model):
    address = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.address

class CryptoCurrency(models.Model):
    basepair = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.basepair

class Fiat(models.Model):
    topair = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.topair


class Wallet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=20, blank=True, default="")
    addresses = models.ManyToManyField(WalletAddress)
    private = models.CharField(max_length=500, blank=True, default="")
    public = models.CharField(max_length=500, blank=True, default="")
    words = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.name + " " + self.user.username


class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.CharField(blank=False, max_length=200)
    balance = models.CharField(blank=True, max_length=20)
    currency = models.CharField(blank=True, max_length=20)
    transaction_id = models.CharField(blank=True, max_length=200)
    transaction_to = models.CharField(blank=True, max_length=200)
    transaction_type = models.CharField(blank=True, max_length=200)
    pending = models.BooleanField(default=True)
    invalid = models.BooleanField(default=False)
    rejected = models.BooleanField(default=False)
    transaction_fee = models.CharField(blank=True, max_length=200, default=0)
    mining_fee = models.CharField(blank=True, max_length=200, default=0)
    #last modification of object when transaction confirmed then datetime is auto_now
    date = models.DateTimeField(auto_now=True)

    def transaction_fee_except_mining_fees(self):
        try:
            transaction_fee = Decimal(self.transaction_fee)
        except:
            transaction_fee = 0

        try:
           mining_fee =  Decimal(self.mining_fee)
        except:
            mining_fee = 0

        if transaction_fee > 0:
            transaction_fee = transaction_fee - mining_fee

        return transaction_fee


    def __str__(self):
        return self.user.username


class PendingTransactions(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.CharField(max_length=200)
    currency = models.CharField(max_length=20)
    transaction_to = models.CharField(max_length=200)
    transaction_fee = models.CharField(blank=True, max_length=200)

    def __str__(self):
        return self.user.username


class VaultWallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    username = models.CharField(blank=False, max_length=200, unique=True)
    name = models.CharField(max_length=20, blank=True, default="")
    addresses = models.ManyToManyField(WalletAddress) 
    private = models.CharField(max_length=500, blank=True, default="")
    public = models.CharField(max_length=500, blank=True, default="")
    words = models.CharField(max_length=500, blank=True, default="")
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


class VaultTransaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.CharField(blank=False, max_length=200)
    balance = models.CharField(blank=True, max_length=20)
    mining_fee = models.CharField(blank=True, max_length=200, default='0')
    currency = models.CharField(blank=True, max_length=20)
    transaction_id = models.CharField(blank=True, max_length=200)
    transaction_to = models.CharField(blank=True, max_length=200)
    transaction_from = models.CharField(blank=True,default='', max_length=200)
    transaction_type = models.CharField(blank=True, max_length=200, default='to_vault')
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username


class MinimunCoin(models.Model):
    site = models.OneToOneField(Site, on_delete=models.CASCADE)
    btc_limit = models.CharField(max_length=200,default='0.0')
    user_alert = models.BooleanField(default=True)
    low_limit_alert = models.BooleanField(default=True)


class MarketLimit(models.Model):
    min_price_limit = models.CharField(max_length=200,default='0.0')
    max_price_limit = models.CharField(max_length=200,default='0.0')
    min_amount_limit = models.CharField(max_length=200,default='0.0')
    max_amount_limit = models.CharField(max_length=200,default='0.0')

class WatchOnlyAddress(models.Model):
    address = models.CharField(max_length=200)

    def __str__(self):
        return self.address


class SGDWallet(models.Model):
    user = models.ForeignKey(User)
    amount = models.FloatField(default=0)

    def __str__(self):
        return self.user.username


class OrderBook(models.Model):
    ORDER_CHOICES = (
        ('0', 'Buy'),
        ('1', 'sell')
    )
    ORDER_MODE = (
        ('0', 'market'),
        ('1', 'limit'),
        ('2', 'stop-limit')
    )

    user = models.ForeignKey(User, related_name='Users')
    exchange_form = models.CharField(max_length=5)
    exchange_to = models.CharField(max_length=5)
    amount = models.FloatField()
    price = models.FloatField()
    limit = models.FloatField()
    is_otc = models.CharField(max_length=2)
    order_type = models.CharField(choices=ORDER_CHOICES, max_length=2)
    order_mode = models.CharField(choices=ORDER_MODE, max_length=2)
    order_time = models.DateTimeField(auto_now_add=True)
    trade_status = models.BooleanField(default=False)
    coins_covered = models.FloatField(default=0)
    trading_fee = models.FloatField(default=0)
    canceled = models.BooleanField(default=False)
    maker = models.BooleanField(default=False)



    def __str__(self):
        return self.user.username

class PendingOrder(models.Model):
    user = models.ForeignKey(User, related_name='pending_order_user')
    pending_amount = models.FloatField()
    order = models.ForeignKey(OrderBook, related_name='pending_order', on_delete=models.CASCADE)
    order_time = models.DateTimeField(auto_now_add=True)
    is_pending = models.BooleanField(default=True)

class OrderMatchingHistory(models.Model):
    processing_order = models.ForeignKey(OrderBook, related_name='processing_order')
    matched_order = models.ForeignKey(OrderBook, related_name='matched_order')
    matching_price = models.FloatField(default=0)
    coins_covered = models.FloatField(default=0)
    trading_fee = models.FloatField(default=0)
    order_matching_time = models.DateTimeField(auto_now_add=True)


class ExchangeTaxRates(models.Model):
    previous_rate = models.FloatField(default=None, null=True, blank=True)
    current_rate = models.FloatField(default=0)
    updated_on = models.DateField(auto_now_add=True, blank=True)
    update_by = models.ForeignKey(User)

    def __str__(self):
        return self.update_by.username



class Notification(models.Model):
    date =  models.DateTimeField(auto_now=True)
    user = models.ManyToManyField(User, through='NotificationUser')
    notification = models.TextField(max_length=128)

    def __str(self):
        return self.notification


class NotificationUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    notification = models.ForeignKey(Notification, on_delete=models.CASCADE)
    is_readed = models.BooleanField(default=False)
    is_pending_notification = models.BooleanField(default=False)


class TransactionTracker(models.Model):
    previous_transaction_count = models.CharField(max_length=128)

class ConfirmFiatTransaction(models.Model): #OTC part transaction
    amount = models.FloatField()
    crypto_amount = models.FloatField()
    fiat_type = models.CharField(max_length=5)
    crypto_type = models.CharField(max_length=5)
    receive_address = models.CharField(max_length=128)
    is_confirm = models.BooleanField(default=False)
    is_cancel = models.BooleanField(default=False)
    receiver = models.ForeignKey(User, related_name='user_fiat_receiver', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name='user_fiat_sender', on_delete=models.CASCADE)
    order = models.ForeignKey(OrderBook, on_delete=models.CASCADE)
    pending_order = models.ForeignKey(PendingOrder, on_delete=models.CASCADE)
    def __str__(self):
        return self.sender.username+"->"+self.receiver.username

class ConfirmCrytpoRequest(models.Model): #OTC part transaction
    amount = models.FloatField()
    crypto_amount = models.FloatField()
    fiat_type = models.CharField(max_length=5)
    crypto_type = models.CharField(max_length=5)
    is_confirm = models.BooleanField(default=False)
    is_cancel = models.BooleanField(default=False)
    receiver = models.ForeignKey(User, related_name='user_crypto_receiver', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name='user_crypto_sender', on_delete=models.CASCADE)
    order = models.ForeignKey(OrderBook, on_delete=models.CASCADE)

class OrderCoverTransaction(models.Model): #CTC part transaction
    amount = models.FloatField()
    user = models.ForeignKey(User, related_name='order_bidder', on_delete=models.CASCADE)
    order = models.ForeignKey(OrderBook, on_delete=models.CASCADE)

class DisputeUpload(models.Model):
    user = models.ForeignKey(User, related_name='defender_user_details')
    user_phonenumber = models.CharField(max_length=20, blank=True, default="")
    user_email = models.CharField(max_length=50, blank=True, default="")
    front_page = models.ImageField()
    description = models.TextField()
    client_phonenumber = models.CharField(max_length=20, blank=True, default="")
    dispute_status = models.CharField(max_length=50, blank=True, default="")

    def __str__(self):
        return self.user.first_name