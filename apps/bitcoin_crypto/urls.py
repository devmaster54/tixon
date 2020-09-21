from django.conf.urls import url
from django.views.generic import TemplateView
from .views import *

urlpatterns = [
    url(r'^settings/', SettingsView.as_view(), name='settings'),
    url(r'^exchange-rate/$', ExchangeRateView.as_view(), name='exchange_rate'),
    url(r'^transactions/$', TransactionListView.as_view(), name='transaction_list'),

    #wallets
    url(r'^wallets/$', WalletsView.as_view(), name='wallets'),
    url(r'^sgd-wallets/$', SGDWalletsView.as_view(), name='sgd_wallets'),
    url(r'^update-sgd-wallet/(?P<pk>\d+)/$', AddSGDView.as_view(), name='update_sgd_wallet'),

    url(r'^sendbcoin/$', SendBTransactionView.as_view(), name='sendbtccoin'),
    url(r'^sendtcoin/$', SendTTransactionView.as_view(), name='sendtxchcoin'),
    url(r'^sendconfirm/$', SendConfirmView.as_view(), name='sendconfirm'),
    url(r'^confirm-withdrawal/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 
        SendEmailConfirmView.as_view(), name='confirm_withdrawal'),
    url(r'^pending-transactions/$', PendingTransactionListView.as_view(), name='pending_transactions'),
    url(r'^confirm-pending-transaction/(?P<pk>\d+)/$', ConfirmPendingTransactionView.as_view(), name='confirm_pending_transaction'),
    url(r'^reject-pending-transaction/(?P<pk>\d+)/$', RejectPendingTransactionView.as_view(), name='reject_pending_transaction'),

    url(r'^all-user-wallet-accounts/$', GetAllUserAddress.as_view(), name='get_all_wallet_users'),
    url(r'^transaction-records/$', TransactionRecordView.as_view(template_name="bitcoin/transaction_record.html"), name='transaction_record'),

    url(r'^set-minimum-limit/$', SetMinimunLimitBTC.as_view(), name='set_minimum_limit'),
    url(r'^set-market-limit/$', SetMarketLimit.as_view(), name='set_market_limit'),
    url(r'^wallet-to-vault/$', WalletToVault.as_view(), name='wallet_to_vault'),
    url(r'^dispute-solve/$', SolveDispute.as_view(), name='dispute_system'),
    url(r'^dispute-raise/$', RaiseDisputeView.as_view(), name='raise_dispute'),
    url(r'^dispute-confirm/$', ConfirmDisputeView.as_view(), name='dispute_confirm'),
    url(r'^dispute-list-my/$', MyListDisputeView.as_view(), name='my_list_dispute'),
    url(r'^dispute-list/$', ListDisputeProcessingView.as_view(), name='list_dispute'),
    url(r'^dispute-approve-list/$', ListDisputeApproveView.as_view(), name='dispute_approve_list'),
    url(r'^dispute-processing-list/$', ListDisputeProcessingView.as_view(), name='dispute_processing_list'),
    url(r'^dispute-rejected-list/$', ListDisputeRejectedView.as_view(), name='dispute_rejected_list'),
    url(r'^dispute-detail/(?P<pk>\d+)/$', DisputeDetailView.as_view(), name='dispute_detail'),
    url(r'^dispute-approve/(?P<pk>\d+)/$', DisputeApproveView.as_view(), name='dispute_approve'),
    url(r'^dispute-reject/(?P<pk>\d+)/$', DisputeRejectView.as_view(), name='dispute_reject'),
    url(r'^dispute-resubmission/(?P<pk>\d+)/$', DisputeResubmitView.as_view(), name='dispute_resubmission'),
    url(r'^confirm-wallet-to-vault/$', ConfirmWalletToVault.as_view(), name='confirm_wallet_to_vault'),
    
    url(r'^vault-confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', 
        WalletToVaultEmailConfirm.as_view(), name='vault_confirm'),
    url(r'^vault-transactions/$', VaultTransactionListView.as_view(), name='vault_transaction_list'),
    url(r'^vault-to-wallet/$', VaultToWalletView.as_view(), name='vault_to_wallet'),
    url(r'^vault-list/$', ListVaultView.as_view(), name='vault_list'),
    
    #pending order urls
    url(r'^cancel-pending-order/(?P<pk>\d+)/$', CancelPendingOrderView.as_view(), name='cancel_pending_order'),

    # records urls
    url(r'^get-user-balance/', GetUserBalanceTransactionView.as_view(), name='get_user_balance'),

    # order urls
    url(r'^stop-limit-order/$', OrderView.as_view(), name='stop_limit_order'),
    url(r'^depthchart/$', AjaxDepthChartView.as_view(), name='depthchart'),
    url(r'^buy-order-list/$', BuyOrderList.as_view(), name='buy_order_list'),
    url(r'^sell-order-list/$', SellOrderList.as_view(), name='sell_order_list'),
    url(r'^delete-order/(?P<pk>\d+)/$', DeleteOrderView.as_view(), name='delete_order'),

    # accept order urls
    url(r'^accept-order/', AcceptOrderView.as_view(), name='accept_order'),
    url(r'^confirm-order/', ConfirmFiatTransactionsView.as_view(), name='confirm_fiat_pendings'),
    url(r'^confirm-request-order/', ConfirmRequestFiatTransactionsView.as_view(), name='confirm_request_pendings'),
    url(r'^cancel-request-order/', CancelRequestFiatTransactionsView.as_view(), name='cancel_requestcrypto_order'),
    url(r'^cancel-request-fiat-order/', CancelAcceptFiatTransactionsView.as_view(), name='cancel_requestfiat_order'),
    url(r'^update-otc-order/', UpdateOtcOrderView.as_view(), name='update_otc_order'),

    #notification urls
    url(r'^notifications/$', NotificationListView.as_view(), name='notifications'),

    #report
    url(r'^report/$', DownloadReport.as_view(), name='report'),
    url(r'^ajax-order-book/$', AjaxOrderBookView.as_view(), name='ajax_order_book'),
]