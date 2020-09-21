from django.contrib import admin
from . models import Wallet, MinimunCoin, ExchangeTaxRates, OrderBook, SGDWallet, Notification, CryptoCurrency, Fiat, ConfirmFiatTransaction, Transaction

# Register your models here.

admin.site.register(Wallet)
admin.site.register(MinimunCoin)
admin.site.register(ExchangeTaxRates)
admin.site.register(OrderBook)
admin.site.register(SGDWallet)
admin.site.register(CryptoCurrency)
admin.site.register(Fiat)
admin.site.register(ConfirmFiatTransaction)
admin.site.register(Transaction)