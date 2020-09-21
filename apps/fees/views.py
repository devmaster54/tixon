import json
import pyotp
from decimal import Decimal

from django.shortcuts import render, HttpResponse, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import UserPassesTestMixin
from django.views.generic import TemplateView
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.contrib.sites.models import Site
from django.views import View
from django.core.mail import send_mail
from django.forms import modelformset_factory
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.utils import six
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from django.urls import reverse
from django.contrib.auth.models import User

from apps.authentication.decorators import check_otp, check_2fa
from apps.authentication.utils import send_otp, _get_pin, send_user_sms, send_admin_sms
from apps.bitcoin_crypto.models import Transaction, PendingTransactions, VaultWallet, MinimunCoin, OrderMatchingHistory
from apps.bitcoin_crypto.utils import *
from .models import *
from .utils import *
from .forms import *



@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class SetMiningFees(UserPassesTestMixin, TemplateView):
    template_name = 'fees/set_mining_fees.html'

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        mining_fees_obj, create = MiningFees.objects.get_or_create(site=Site.objects.get_current())

        if create:
            set_mining_fees(Decimal(mining_fees_obj.mining_fees))

        context['mining_fees'] = mining_fees_obj.mining_fees

        return context

    def post(self, request, *args, **kwargs):
        value = request.POST.get('mining_fees')

        try:
            decimal_value = Decimal(value)
        except:
            return HttpResponse(json.dumps({"error": "Invalid Amount."}), content_type='application/json')

        mining_fees_obj, create = MiningFees.objects.get_or_create(site=Site.objects.get_current())

        set_mining_fees(decimal_value)

        mining_fees_obj.mining_fees = value
        mining_fees_obj.save()

        return HttpResponse(json.dumps({"success": True}), content_type='application/json')


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class SetTransactionFee(UserPassesTestMixin, View):

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):

        form = TransactionFeeForm()
        TransactionFeeRangeFormSet = modelformset_factory(TransactionFeeRange, fields=('limit', 'value', 'fees'),
            min_num=1, extra=0, validate_min=True)
        formset = TransactionFeeRangeFormSet(prefix='transaction_fee_formset', queryset=TransactionFeeRange.objects.none())
        context = {
            'form' : form,
            'formset': formset
        }

        return render(request, 'fees/set_transaction_fees.html', context)

    def post(self, request, *args, **kwargs):
        form = TransactionFeeForm(request.POST)
        TransactionFeeRangeFormSet = modelformset_factory(TransactionFeeRange, fields=('limit', 'value', 'fees'),
            min_num=1, extra=0, validate_min=True)

        formset = TransactionFeeRangeFormSet(request.POST, prefix='transaction_fee_formset', queryset=TransactionFeeRange.objects.none())

        if form.is_valid() and formset.is_valid():

            transaction_fee_obj = form.save(commit=False)

            if transaction_fee_obj.fee_type == 'taker':
                transaction_fee_obj.currency = 'sgd'
            else:
                transaction_fee_obj.currency = 'btc'

            print(transaction_fee_obj)
            print(transaction_fee_obj.currency)

            transaction_fee_obj.save()

            for form in formset:
                form = form.save(commit=False)
                form.transaction_fee = transaction_fee_obj
                try:
                    form.save()
                except:
                    transaction_fee_obj.delete()
                    status =  'Limit and value pair needs to be unique'
                    return HttpResponse(json.dumps({"status": status}), content_type='application/json')

            status = 'success'
        else:

            status =  'Something Went Wrong'

            for field in form:
                for error in field.errors:
                    status = error

            for error in form.non_field_errors():
                 status = error

            for form in formset:
                for field in form:
                    for error in form.errors:
                        status = error

            for error in formset.non_form_errors():
                status = error

        return HttpResponse(json.dumps({"status": status}), content_type='application/json')


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class ListTransactionFee(UserPassesTestMixin, View):

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        transaction_fees = TransactionFee.objects.all()
        context = {
            'transaction_fees' : transaction_fees
        }
        return render(request, 'fees/list_transaction_fees.html', context)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class DeleteTransactionFee(UserPassesTestMixin, View):

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        try:
            transaction_fee = get_object_or_404(TransactionFee, pk=self.kwargs['pk'])
        except:
            return HttpResponse(json.dumps({"status": 'Object not Found'}), content_type='application/json')

        try:
            transaction_fee.delete()
        except:
            return HttpResponse(json.dumps({"status": 'Object can not delete'}), content_type='application/json')

        return HttpResponse(json.dumps({"status": 'success'}), content_type='application/json')


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class TransactionFeeWithdrawalListView(UserPassesTestMixin, View):

    template_name = 'fees/transactions_fee_withdrawal_list.html'

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        access = create_connection()
        transactions = access.listtransactions('transaction fee collector')
        send_list = Transaction.objects.filter(transaction_type='fee_withdrawal')
        trade_fee = OrderMatchingHistory.objects.filter(trading_fee__gt=0.0)

        recive_list = [txn for txn in transactions if txn['category'] == 'receive']

        context = {
            'send_list': send_list,
            'recive_list': recive_list,
            'trade_fee': trade_fee
        }
        return render(request, self.template_name, context)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class SendTransactionFeeView(UserPassesTestMixin, TemplateView):
    template_name = 'fees/withdraw_fee.html'

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def post(self, request, *args, **kwargs):
        address = request.POST.get('to')
        request.session['to'] = address

        amount = Decimal(request.POST.get('amount'))
        request.session['amount'] = request.POST.get('amount')

        access = create_connection()
        valid = access.validateaddress(address)
        validate_balance = get_fee_balance()

        if valid['isvalid'] and validate_balance >= amount:
            return HttpResponse(json.dumps({"success":True}), content_type='application/json')
        if valid['isvalid']:
            return HttpResponse(json.dumps({"error":"Insufficient balance"}), content_type='application/json')
        if validate_balance >= amount:
            return HttpResponse(json.dumps({"error":"Please enter a valid address"}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({"error":"Please verify the data"}), content_type='application/json')


class EmailTokenGenerator(PasswordResetTokenGenerator):
    """ Overriding default Password reset token generator for email confirmation"""
    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk) + six.text_type(timestamp)) +  six.text_type(user.is_active)

email_token = EmailTokenGenerator()


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class SendConfirmView(UserPassesTestMixin, View):

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def post(self, request, *args, **kwargs):
        
        sms_redirect = False

        if request.POST.get('to') and request.POST.get('amount'):
            request.session['address'] = request.POST.get('to')
            request.session['amount'] = request.POST.get('amount')

            try:
                del request.session['fee-withdraw-otp-verified']
            except:
                pass

        if request.user.sms_otp:

            otp_verified = request.session.get('fee-withdraw-otp-verified', False)
            
            if not otp_verified and  self.request.POST.get('value') and not request.POST.get('resend-otp'):
                if self.request.POST.get('value') == self.request.session['fee-withdraw-otp']:
                    request.session['fee-withdraw-otp-verified'] = True
                    sms_redirect = True
                else:
                    return HttpResponse(json.dumps({"status":"otp-not-verified"}), content_type='application/json')

            elif not otp_verified:
                pin =  _get_pin(self)
                self.request.session['fee-withdraw-otp'] = pin
                send_otp(self, pin, self.request.user.phone_number)
                return HttpResponse(json.dumps({"status":"get-otp"}), content_type='application/json')

        if request.user.google_2fa:

            if self.request.POST.get('value') and not sms_redirect:
                totp_code = self.request.POST.get('value', None)
                totp = pyotp.TOTP(self.request.user.google_2fa_key)

                if not totp.verify(totp_code):
                    return HttpResponse(json.dumps({"status":"totp-not-verified"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"status":"get-totp"}), content_type='application/json')

        pending_transaction = PendingTransactions.objects.create(user=request.user, amount=request.session['amount'],
            currency=request.session['base_pair'], transaction_to=request.session['address'])

        token = email_token.make_token(request.user)
        uidb64 = urlsafe_base64_encode(force_bytes(pending_transaction.pk)).decode("utf-8")

        html_message = render_to_string('bitcoin/confirm-withdrawal-email.html', {
            'pending_transaction': pending_transaction,
            'uri': reverse('fees:confirm_fee_withdrawal_email', kwargs={'uidb64':uidb64, 'token': token}),
            'domain': self.request.scheme+"://"+"tixon.exchange",
        })

        try:
            del request.session['fee-withdraw-otp-verified']
        except:
            pass

        try:
            send_mail('Confirm Withdrawal',
                '',
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
                html_message = html_message,
                fail_silently=False
            )
            return HttpResponse(json.dumps({"success":True}), content_type='application/json')
        except:
            return HttpResponse(json.dumps({"error":"something went wrong"}), content_type='application/json')


class SendEmailConfirmView(View):

    def get(self, request, *args, **kwargs):
        pk = force_text(urlsafe_base64_decode( kwargs.get('uidb64')))
        token = kwargs.get('token')
        pending_transaction = get_object_or_404(PendingTransactions, pk=pk)
        context = {'success': False}

        if email_token.check_token(pending_transaction.user, token):

            balance = get_fee_balance()
            access = create_connection()
            address = pending_transaction.transaction_to
            amount = Decimal(pending_transaction.amount)

            if balance < amount:
                context = {'message': 'Insufficient Balance.'}
                return render(request,'bitcoin/transaction_confirm.html', context)

            btc_limit_obj, create = MinimunCoin.objects.get_or_create(site=Site.objects.get_current())
            minimum_limit = Decimal(btc_limit_obj.btc_limit)

            balance_status = get_account_balance() - amount
            if (get_account_balance() < amount) or (balance_status < minimum_limit):
                balance = balance - amount
                
                if (get_account_balance() < amount):
                    message = "Requesting more amount than existing balance. Please Visit TixonExchange Wallet Update page to view the Amount need to maintain mininum Balance."
                    email_title = 'Insufficient Fund in Hot Wallet'
                    context = {'success': True}
                else:
                    message = 'Minimum Balance limit Exceed in TixonExchange. Please Update wallet Amount'
                    email_title = 'Minimum Balance limit Exceed'

                valid = access.validateaddress(address)

                if valid['isvalid']:
                    Transaction.objects.create(user=pending_transaction.user, currency="btc", balance=balance, 
                   amount=amount, transaction_type="fee_withdrawal", transaction_id='', transaction_to=address, pending=True)
                    context = {'success': True}
                else:
                    context = {'message': 'Transaction Failed. Invalid Address'}
                            
                pending_transaction.delete()

                if btc_limit_obj.low_limit_alert:

                    users = User.objects.filter(is_superuser=True).exclude(phone_number="", email="")

                    for admin_user in users:

                        send_mail(email_title,
                            message,
                            settings.DEFAULT_FROM_EMAIL,
                            [admin_user.email],
                            fail_silently=True
                        )

                        send_admin_sms(admin_user.phone_number, message)

                    btc_limit_obj.low_limit_alert = False
                    btc_limit_obj.save()

                return render(request,'bitcoin/transaction_confirm.html', context)

            valid = access.validateaddress(address)

            if valid['isvalid']:
                balance = balance - amount
                Transaction.objects.create(user=pending_transaction.user, currency="btc", balance=balance, 
                   amount=amount, transaction_type="fee_withdrawal", transaction_id='', transaction_to=address, pending=True)
                pending_transaction.delete()
                context = {'success': True}

        return render(request,'bitcoin/transaction_confirm.html', context)