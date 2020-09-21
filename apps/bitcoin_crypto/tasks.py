from __future__ import absolute_import, unicode_literals
from celery import task

from .utils import create_connection
from .models import Notification, NotificationUser, TransactionTracker, Transaction
from apps.authentication.models import User
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from datetime import datetime, timedelta
from .utils import complete_pending_transaction
from django.utils import timezone
from decimal import Decimal

@task()
def notify_deposit():
    access = create_connection()
    wallet_info = access.getwalletinfo()
    current_count = wallet_info['txcount']
    print('current count', current_count)

    if TransactionTracker.objects.all().exists():

        tansaction_tracker_obj = TransactionTracker.objects.latest('id')

        previous_count = int(tansaction_tracker_obj.previous_transaction_count)
        print('previous count', previous_count)

        if  previous_count < current_count:

            transaction_list= access.listtransactions("*", (current_count-previous_count) * 4)

            #processing withdrawal that confired by node
            # withdrawal_transaction_list = [transaction for transaction in transaction_list if transaction['category'] == 'send' and 
            # transaction['account'] != 'transaction fee collector'][-(current_count-previous_count):]

            # confirmed_withdrawal_transaction_list = [transaction for transaction in withdrawal_transaction_list if transaction['confirmations'] > 0]

            # for confirmed_withdrawal in confirmed_withdrawal_transaction_list:
            #     print('confirmed withdrawal')
            #     print(confirmed_withdrawal)
            #     Transaction.objects.filter(transaction_id=confirmed_withdrawal['txid'], 
            #         transaction_type='withdrawal').update(pending=False)


            transaction_list = [transaction for transaction in transaction_list if transaction['category'] == 'receive' and 
            transaction['account'] != 'transaction fee collector'][-(current_count-previous_count):]

            print('cliped list')
            print(transaction_list)

            confirmed_transactions = [transaction for transaction in transaction_list if transaction['confirmations'] > 0]
            print('confirmed transactions')
            print(confirmed_transactions)

            for new_transaction in confirmed_transactions:
                print('looping transaction')
                print(new_transaction)
                
                if User.objects.filter(username=str(new_transaction['account'])).exists():
                    user = User.objects.get(username=str(new_transaction['account']))
                    print(user.username)

                    #creating user notification
                    notification_txt = 'You have received <b>%s BTC</b>' %(new_transaction['amount'])
                    notification_txt += '<br>Transaction Id : <b>%s</b>' %(new_transaction['txid'])
                    print('notification text', notification_txt)
                    notification = Notification.objects.create(notification=notification_txt)
                    NotificationUser.objects.create(notification=notification, user=user)

                    #sending email notification
                    html_message = render_to_string('bitcoin/notification_email.html', {
                        'user': user,
                        'notification_txt' : notification_txt
                    })

                    send_mail('New Deposit',
                        '',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        html_message = html_message,
                        fail_silently=True
                    )

                    # creating transaction instance in model
                    new_balance = access.getbalance(user.username)
                    date_time = datetime.fromtimestamp(float(new_transaction['time']))
                    Transaction.objects.create(user=user, date=date_time, currency="btc", balance=new_balance, transaction_type='deposit', 
                        amount=new_transaction['amount'], transaction_fee='0', transaction_id=new_transaction['txid'], pending=False)

                    # modifying tracker count 
                    new_count = int( TransactionTracker.objects.get(id=tansaction_tracker_obj.pk).previous_transaction_count) + 1
                    TransactionTracker.objects.update(id=tansaction_tracker_obj.pk, previous_transaction_count=new_count)
                    print('traker count modified', TransactionTracker.objects.last().previous_transaction_count)

    else:
        TransactionTracker.objects.create(previous_transaction_count=str(current_count))


@task()
def auto_approve_transactions():
    now = timezone.now()
    print(now)
    pending_transactions = Transaction.objects.filter(pending=True)
    print(pending_transactions)
    access = create_connection()

    for transaction in pending_transactions:
        print(transaction.date + timedelta(minutes=10))
        if transaction.date + timedelta(minutes=10) <= now:
            try:
                amount = Decimal(transaction.amount)
            except:
                amount = Decimal(0)

            transaction_fee = Decimal(transaction.transaction_fee)

            if access.getbalance() >= (amount+transaction_fee):
                if complete_pending_transaction(transaction) == True:
                    notification = Notification.objects.create(notification='Withdrawal amount %s BTC to address %s has approved by admin'
                        %(transaction.amount, transaction.transaction_to))
                    NotificationUser.objects.create(notification=notification, user=transaction.user)
            else:
                return


@task()
def notify_pending_transaction():
    pending_transactions = Transaction.objects.filter(pending=True)

    if pending_transactions.exists():

        latest_transaction = pending_transactions.latest('date')
        admin_users = User.objects.filter(is_superuser=True)
        for user in admin_users:
            notification_objs = Notification.objects.filter(notificationuser__is_pending_notification=True, notificationuser__user=user)
            if notification_objs.exists():
                latest_notification = notification_objs.latest('date')

                if latest_notification.date <= latest_transaction.date:
                    notification_user = NotificationUser.objects.get(notification=latest_notification, user=user)
                    if notification_user.is_readed == True:
                        new_notification = Notification.objects.create(notification='You have %s pending withdrawal to process' %pending_transactions.count())
                        NotificationUser.objects.create(notification=new_notification, user=user, is_pending_notification=True)

                        print('new pending notification created')
                    else:
                        latest_notification.notification = 'You have %s pending withdrawal to process' %pending_transactions.count()
                        latest_notification.save()

                        print('pending notification updated')

            else:
                notification_obj = Notification.objects.create(notification='You have %s pending withdrawal to process' %pending_transactions.count())
                NotificationUser.objects.create(user=user, notification=notification_obj, is_pending_notification=True)

                print('first pending notification created')