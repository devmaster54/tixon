from django.conf.urls import url

from .views import *

urlpatterns = [
    url(r'^mining-fees/$', SetMiningFees.as_view(), name='mining_fees'),
    url(r'^set-transaction-fee/$', SetTransactionFee.as_view(), name='set_transaction_fee'),
    url(r'^transaction-fee-list/$', ListTransactionFee.as_view(), name='transaction_fee_list'),
    url(r'^delete-transaction-fee/(?P<pk>\d+)/$', DeleteTransactionFee.as_view(), name='delete_transaction_fee'),
    url(r'^transaction-fee-withdrawal-list/$', TransactionFeeWithdrawalListView.as_view(), name='transaction_fee_withdrawal_list'),

    url(r'^withdraw-fee/$', SendTransactionFeeView.as_view(), name='withdraw_fee'),
    url(r'^withdraw-fee-confirm/$', SendConfirmView.as_view(), name='withdraw-fee-confirm'),
    url(r'^confirm-fee-withdrawal-email/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 
        SendEmailConfirmView.as_view(), name='confirm_fee_withdrawal_email'),
]