import random
import pytz

from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.views import PasswordChangeView, PasswordResetView, \
    PasswordResetConfirmView, LoginView, login
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect, render_to_response, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView, UpdateView, CreateView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView
from django.views import View
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils import six
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.shortcuts import get_object_or_404
from django.template import RequestContext
from django.urls import reverse_lazy
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin, AccessMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import UserPassesTestMixin
from django.utils.translation import ugettext_lazy as _

from twilio.rest import Client

from apps.authentication.forms import PasswordChangeForm, CustomSetPasswordForm, ContactUsForm
from apps.authentication.forms import ResendActivationForm, RegistrationForm, ProfileEditForm, Check2FAForm, KYCUploadForm, \
     BankAccountForm, PaypalAccountForm, WechatAccountForm, AlipayAccountForm
from apps.authentication.models import User, AccessLog, KYCUpload, Profile, BankAccount, PreviousPassword, PaypalAccount, WechatAccount, AlipayAccount
from apps.authentication.decorators import check_otp, check_2fa
import pyotp

from django.http import JsonResponse
from apps.authentication.utils import send_otp, _get_pin, send_user_sms
import json
from apps.bitcoin_crypto.models import Notification, NotificationUser, SGDWallet
from .postalcodes import POSTCODES_REGEX


class RegistrationView(FormView):
    """
    User registration view.

    """
    form_class = RegistrationForm
    success_url = None
    template_name = 'authentication/register.html'

    def form_valid(self, form):
        new_user = form.save(commit=False)
        if new_user:

            new_user.is_active = False
            new_user.save()

            SGDWallet.objects.create(user=new_user)


            token = account_activation_token.make_token(new_user)
            html_message = render_to_string('authentication/email_varification.html', {
                'user': new_user,
                'domain': self.request.scheme+"://"+"tixon.exchange",
                'uid': urlsafe_base64_encode(force_bytes(new_user.pk)).decode("utf-8"),
                'token': token,
                'expiration_days': settings.PASSWORD_RESET_TIMEOUT_DAYS
            })
            print(html_message, "this is verify message", new_user, settings.DEFAULT_FROM_EMAIL)
            try:
                send_mail('Confirm Registration',
                          '',
                          settings.DEFAULT_FROM_EMAIL,
                          [new_user.email],
                          html_message = html_message,
                          fail_silently=False
                          )
            except:
                pass

            x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = self.request.META.get('REMOTE_ADDR')

            browser_family = self.request.user_agent.browser.family
            os_family = self.request.user_agent.os.family
            AccessLog.objects.create(user=new_user, ip=ip, device=browser_family, os=os_family)

            return render_to_response('authentication/success.html',context={'email':new_user.email})
        else:
            return redirect(reverse('signup'))


class GetStartedView(View):
    """
        getstarted link in home page
    """

    def post(self, request, *args, **kwarga):
        form = RegistrationForm(initial={'email': request.POST.get('email')})
        form.fields['password1'].widget.attrs['autofocus'] = 'true'

        return render(self.request,"authentication/register.html",{'form': form})


class TwoFactorAuthenticationView(TemplateView):
    template_name = "authentication/mobile.html"

    def get(self, request):
        try:
            del self.request.session['otp']
        except:
            pass
        return render(self.request,"authentication/mobile.html")

    def post(self,request,*args,**kwargs):
        number = self.request.POST.get('phone_number')
        if number:
            User.objects.filter(id = self.request.user.id).update(phone_number=number)
            pin =  _get_pin(self)
            self.request.session['otp'] = pin
            try:
                send_otp(self, pin, number)
            except:
                User.objects.filter(id = self.request.user.id).update(phone_number='')
                return JsonResponse({'status':False, "error":"Please Check the Phone Number"})
            return JsonResponse({'status':True})
        return JsonResponse({'status':False})


class CheckTwoFactorAuthenticationView(TemplateView):
    template_name = "authentication/otp.html"

    def get(self, request):
        return render(self.request,"authentication/otp.html")


    def post(self, request, *args, **kwargs):

        print('otp submitted')

        if not self.request.POST.get('otp'):

            context ={
                'otp_required': 'This field is required'
            }

        elif self.request.POST.get('otp') == self.request.session['otp']:

            print('success otp')
            del self.request.session['otp']
            self.request.session['otp-verified'] = True
            return redirect(reverse('welcome'))
        else:
            print('otp not matching')
            context ={
                'error': 'Invaid OTP'
            }

        return render(self.request,"authentication/otp.html",context)


class SendOTP(View):

    def get(self, request, *args, **kwargs):
        pin = _get_pin(self)
        self.request.session['otp'] = pin

        try:
            send_otp(self, pin, self.request.user.phone_number)
        except:
            context={
                'title': 'OTP send failed'
            }
            return render(request, 'authentication/sms_otp_error.html', context)

        return redirect(reverse('check_otp'))



class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """ Overriding default Password reset token generator for email confirmation"""
    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk) + six.text_type(timestamp)) +  six.text_type(user.is_active)

account_activation_token = AccountActivationTokenGenerator()

class ConfirmSignUpView(View):
    """ Confirming sign up via link provided in email"""
    template_name = 'authentication/email_verified.html'

    def get(self, request, *args, **kwargs):
        """ Ckecking token and conforming account activation"""
        pk = force_text(urlsafe_base64_decode( kwargs.get('uidb64')))
        token = kwargs.get('token')
        user = get_object_or_404(User, pk=pk)
        if account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return render(request, self.template_name, {'error': False})
        else:
            return render(request,self.template_name, {'error': True})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCUploadView(View):

    template_name = "authentication/kyc_upload.html"

    def get(self, request, *args, **kwargs):
        """
            provide kyc forms to provide kyc details
        """
        profile_form = ProfileEditForm()
        kyc_form = KYCUploadForm()

        context = {
            'profile_form': profile_form,
            'kyc_form': kyc_form,
            'timezones': pytz.common_timezones
        }

        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        """
            kyc details uploading verifing the data and reconfirm by user
        """

        profile_form = ProfileEditForm(request.POST, request.FILES)
        kyc_form = KYCUploadForm(request.POST, request.FILES)

        confirmation = request.POST.get('confirmation')
        timezone = request.POST.get('timezone')

        if profile_form.is_valid() and kyc_form.is_valid():

            pre_profile = Profile.objects.filter(user=self.request.user)
            if pre_profile.exists():
                pre_profile.delete()

            profile = profile_form.save(commit=False)
            profile.user = self.request.user
            profile.save()

            pre_kyc = KYCUpload.objects.filter(user=self.request.user)
            if pre_kyc.exists():
                pre_kyc.delete()

            kyc = kyc_form.save(commit=False)
            kyc.user = self.request.user
            kyc.save()

            context = {
                'profile_form': ProfileEditForm(instance=profile),
                'kyc_form': KYCUploadForm(instance=kyc),
                'confirm_data' : True,
                'timezones': pytz.common_timezones
            }
            return render(request, self.template_name, context)
        else:
            context = {
                'profile_form': profile_form,
                'kyc_form': kyc_form,
                'timezones': pytz.common_timezones
            }
            return render(request, self.template_name, context)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class ZipRgxView(View):

    def post(self, request, *args, **kwargs):
        country_code = request.POST.get('country_code')
        print(country_code)
        regex = POSTCODES_REGEX.get(country_code, None)

        regex = regex[1:-1] if regex else ""
        print(regex)
        return JsonResponse({'regex': regex})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class ConfirmKYCUpload(View):

    def get(self, request, *args, **kwargs):
        if request.user.get_user_profile and request.user.get_user_details and \
                self.request.user.kyc_verified == 'not-verified':
            self.request.user.kyc_verified = 'processing'
            self.request.user.save()

            notification = Notification.objects.create(notification="New KYC submission by %s" %request.user.username)
            for user in User.objects.filter(is_superuser=True):
                NotificationUser.objects.create(user=user, notification=notification)

            return redirect(reverse('kyc_detail',kwargs={'pk': request.user.pk}))
        else:
            return redirect(reverse('kyc_upload'))


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCDetailView(View):

    template_name = "authentication/profile.html"

    def get(self, request, *args, **kwargs):
        user = User.objects.get(pk=self.kwargs['pk'])
        context = {
            'user': user
        }

        return render(request, self.template_name, context)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCProcessingListView(UserPassesTestMixin, View):
    """
        listing all kyc submission
    """
    template_name = "authentication/kyc_list.html"

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        processing_list = User.objects.filter(kyc_verified='processing')
        print(processing_list)
        context = {
            'processing_list': processing_list,
            'processing': True
        }
        return render(request, self.template_name, context)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCActiveListView(UserPassesTestMixin, View):
    """
        listing all approved kyc submission
    """
    template_name = "authentication/kyc_list.html"

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        active_list = User.objects.filter(kyc_verified='verified')
        print(active_list)
        return render(request, self.template_name, {'active_list': active_list, 'active': True})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCRejectedListView(UserPassesTestMixin, View):
    """
        listing rejected kyc uploads
    """
    template_name = "authentication/kyc_list.html"

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        rejected_list = User.objects.filter(kyc_verified='rejected')
        return render(request, self.template_name, {'rejected_list': rejected_list, 'rejected': True})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCApproveView(UserPassesTestMixin, View):

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        user = User.objects.get(pk=self.kwargs['pk'])
        user.kyc_verified = 'verified'
        user.save()

        notification = Notification.objects.create(notification=_("KYC details approved by admin."))
        NotificationUser.objects.create(user=user, notification=notification)

        messages.success(self.request, '%s KYC details Verified.' %user.email)
        return redirect(reverse('kyc_list'))


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCRejectView(UserPassesTestMixin, View):
    template_name = 'authentication/reject_kyc.html'

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        user = get_object_or_404(User, pk=self.kwargs['pk'])
        context = {
            'user' : user
        }
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):

        feedback = request.POST.get('feedback', False)
        user = get_object_or_404(User, pk=self.kwargs['pk'])

        if not feedback:
            context ={
                'user': user,
                'feedback_error': 'This field is required'
            }
            return render(request, self.template_name, context)

        user.kyc_verified = 'rejected'
        user.save()

        notification = Notification.objects.create(notification=
                                                   "<b>KYC details rejected by admin</b><br>%s<br>please contact site admistrator for more details" %feedback)
        NotificationUser.objects.create(user=user, notification=notification)

        messages.success(self.request, '%s KYC details Rejected.' %user.email)
        return redirect(reverse('kyc_list'))


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class KYCResubmitView(UserPassesTestMixin, View):
    template_name = 'authentication/kyc_resubmission.html'

    def test_func(self):
        if not self.request.user.is_superuser:
            raise PermissionDenied()
        return True

    def get(self, request, *args, **kwargs):
        user = get_object_or_404(User, pk=self.kwargs['pk'])
        context = {
            'user' : user
        }
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):

        feedback = request.POST.get('feedback', False)
        user = User.objects.get(pk=self.kwargs['pk'])

        if not feedback:
            context ={
                'user': user,
                'feedback_error': 'This field is required'
            }
            return render(request, self.template_name, context)

        user.kyc_verified = 'not-verified'
        user.save()

        notification = Notification.objects.create(notification=
                                                   "<b>KYC details resubmission require accessing website features</b><br>%s<br>More information contact administrator" %feedback)
        NotificationUser.objects.create(user=user, notification=notification)

        messages.success(self.request, '%s KYC details resubmission requested.' %user.email)
        return redirect(reverse('kyc_list'))


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EnableMobileOtp(TemplateView):
    """enable mobile otp"""
    template = 'authentication/enable_otp.html'


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class DesableMobileOtp(TemplateView):
    """desable mobile otp"""
    template_name = 'authentication/disable-sms.html'




@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EmableGoogle2fa(TemplateView):
    """enable google two factor authentication"""
    template_name = 'authentication/enable_google_2fa.html'

    def get(self, request, *args, **kwargs):
        user = self.request.user
        if not user.google_2fa_key:
            secret_key = pyotp.random_base32()
            user.google_2fa_key = secret_key
            user.save()

        # qr_url = pyotp.totp.TOTP(user.google_2fa_key).provisioning_uri(user.email, issuer_name="bullxchange")

        return render(request, self.template_name, {'user': user})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class AjaxEmableGoogle2fa(View):

    def get(self, request, *args, **kwargs):
        otp_code = self.request.GET.get('otp')
        print(otp_code)
        google_2fa_key = self.request.user.google_2fa_key
        totp = pyotp.TOTP(google_2fa_key)

        if totp.verify(otp_code):
            self.request.user.google_2fa = True
            self.request.user.save()
            self.request.session['totp-verified'] = True
            response = JsonResponse({'status': True})
            return response
        else:
            response = JsonResponse({'status': False})
            return response


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class DesableGoogle2fa(View):
    """desable google two factor authentication"""
    template_name = 'authentication/desable_2fa.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {})

    def post(self, request, *args, **kwargs):
        form = Check2FAForm(request.POST, user=request.user)

        if form.is_valid():
            user = self.request.user
            user.google_2fa = False
            user.save()
            return JsonResponse({'status': True})
        else:
            return JsonResponse({'status': False})


class VerifyGoogle2fa(AccessMixin, TemplateView):
    """ verifying 2fa password"""
    template_name = 'authentication/google_2fa.html'

    def post(self, request, *args, **kwargs):
        otp_code = self.request.POST.get('otp')
        google_2fa_key = self.request.user.google_2fa_key
        totp = pyotp.TOTP(google_2fa_key)

        if totp.verify(otp_code):
            self.request.session['totp-verified'] = True
            return redirect(reverse('welcome'))
        else:
            return render(request, self.template_name, {'error': 'Invalid Code'})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class PasswordChangeView(PasswordChangeView):
    form_class = PasswordChangeForm

    def form_valid(self, form):

        super_data = super().form_valid(form)

        #email notification of password change
        html_message = render_to_string('authentication/password_changed_email.html', {
            'user': self.request.user,
            'contact_us': self.request.build_absolute_uri(reverse('contact_us'))
        })

        send_mail('Password Changed',
                  '',
                  settings.DEFAULT_FROM_EMAIL,
                  [self.request.user.email],
                  html_message = html_message,
                  fail_silently=True
                  )

        return super_data


class CustomPasswordResetView(PasswordResetView):

    def form_valid(self, form):

        email = form.cleaned_data['email']
        user = User.objects.filter(email=email)

        if not user.exists():
            form.add_error('email', 'Email address not exist in records')
            return self.form_invalid(form)

        return super().form_valid(form)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class Ajax2FAEnable(View):

    def post(self,request,*args,**kwargs):
        number = self.request.POST.get('phone_number')
        if number:
            User.objects.filter(id = self.request.user.id).update(phone_number=number)
            pin =  _get_pin(self)
            self.request.session['otp'] = pin
            try:
                send_otp(self, pin, number)
            except:
                User.objects.filter(id = self.request.user.id).update(phone_number='')
                return JsonResponse({'status':False, "error":"Please Check the Phone Number"})
            return JsonResponse({'status':True})


class AjaxOTPValidation(View):

    def post(self, request, *args, **kwargs):
        if self.request.POST.get('otp') == self.request.session['otp']:
            del self.request.session['otp']
            self.request.session['otp-verified'] = True
            User.objects.filter(id = self.request.user.id).update(sms_otp=True)
            # device = self.request.META['HTTP_USER_AGENT']
            # ip = self.request.META['REMOTE_ADDR']
            # AccessLog.objects.create(user= self.request.user, device=device, ip=ip)
            return JsonResponse({'status':True,'success_url':reverse('coins:settings')})
        return JsonResponse({'status':False})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class AjaxSend2FADisbleOTP(View):


    def get(self, request, *agrs, **kwargs):
        return JsonResponse(send_user_sms(self))

    def post(self, request, *agrs, **kwargs):
        if self.request.POST.get('otp') == self.request.session['otp']:
            if request.user.check_password(self.request.POST.get('password')):
                del self.request.session['otp']
                del self.request.session['otp-verified']
                User.objects.filter(id = self.request.user.id).update(sms_otp=False)
                User.objects.filter(id=self.request.user.id).update(phone_number='')
                return JsonResponse({'status':True,'success_url':reverse('coins:settings')})
            else:
                return JsonResponse({'status':False,'message':'Invalid user authentication password'})
        else:
            return JsonResponse({'status':False,'message':'Invalid OTP, Check it again'})


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class UpdateMobileNumber(LoginRequiredMixin, TemplateView):

    template_name = 'authentication/update-mobile.html'


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class AjaxUpdateMobileNumber(View):


    def get(self, request, *agrs, **kwargs):
        return JsonResponse(send_user_sms(self))

    def post(self, request, *agrs, **kwargs):
        if self.request.POST.get('otp') == self.request.session['otp']:
            if request.user.check_password(self.request.POST.get('password')):
                del self.request.session['otp']
                User.objects.filter(id=self.request.user.id).update(phone_number=self.request.POST.get('phone_number'))
                return JsonResponse({'status':True,'success_url':reverse('coins:settings')})
            else:
                return JsonResponse({'status':False,'message':'Invalid user authentication password'})
        else:
            return JsonResponse({'status':False,'message':'Invalid OTP, Check it again'})


class CustomPasswordResetConfirmView(PasswordResetConfirmView):

    form_class = CustomSetPasswordForm

    def form_valid(self, form):
        super_form = super().form_valid(form)

        #email notification of password change
        html_message = render_to_string('authentication/password_changed_email.html', {
            'user': self.user,
            'contact_us': self.request.build_absolute_uri(reverse('contact_us'))
        })

        send_mail(_('Password Changed'),
                  '',
                  settings.DEFAULT_FROM_EMAIL,
                  [self.user.email],
                  html_message = html_message,
                  fail_silently=True
                  )

        return super_form



class CustomLoginView(LoginView):

    template_name = 'authentication/signin.html'

    def post(self, request, *args, **kwargs):
        super_data = super(CustomLoginView, self).post(request, *args, **kwargs)

        if request.user.is_authenticated:
            request.session['base_pair']='BTC'

            if request.user.sms_otp:
                pin = _get_pin(self)
                self.request.session['otp'] = pin

                try:
                    send_otp(self, pin, self.request.user.phone_number)
                except:
                    context={
                        'title': 'OTP send failed'
                    }
                    return render(request, 'authentication/sms_otp_error.html', context)
            
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')

            browser_family = request.user_agent.browser.family
            os_family = request.user_agent.os.family

            if not AccessLog.objects.filter(user=request.user, ip=ip, device=browser_family, os=os_family).exists():
                access_obj = AccessLog.objects.create(user=request.user, ip=ip, device=browser_family, os=os_family)
                #email notification of password change
                html_message = render_to_string('authentication/new_login_alert_email.html', {
                    'user': self.request.user,
                    'contact_us': self.request.build_absolute_uri(reverse('contact_us')),
                    'access_obj': access_obj
                })

                send_mail(
                    _('New login for TixonExchange'),
                    '',
                    settings.DEFAULT_FROM_EMAIL,
                    [self.request.user.email],
                    html_message = html_message,
                    fail_silently=True
                )
                
        if request.POST.get('remember_me', None):
            request.session.set_expiry(0)

         
        return super_data

    def get(self, request, *args, **kwargs):
        """
            verifing authenticated user and 2fa verified. if not then redirecting to login
            else redirecting to dashboard
        """
        if request.user.is_authenticated:
            verified = True
            if request.user.sms_otp:
                verified = request.session.get('otp-verified', False)

            if request.user.google_2fa:
                verified = request.session.get('totp-verified', False)

            if verified:
                return  redirect(reverse('get_started'))

        return super().get(request, *args, **kwargs)


@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class BankAccountView(View):

    def post(self, request, *args, **kwargs):
        form = BankAccountForm(request.POST)
        if form.is_valid():
            user_profile = Profile.objects.filter(user=self.request.user)
            if user_profile.exists():
                if  request.POST["account_holder_name"] != user_profile[0].full_name:
                    return JsonResponse({'errors_dict': {'account_holder_name':_('Must be the same as the id name')}})
            else :
                return JsonResponse({'errors_dict': {'account_holder_name':_('You need to verify your account')}})        
            form = form.save(commit=False)
            form.user = request.user
            form.save()
            return JsonResponse({'success': True})
        else:

            if form.errors:
                errors_list = [{errors : error} for errors in form.errors for error in form.errors[errors]]

            print(errors_list)

            return JsonResponse({'errors_dict': form.errors})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class PaypalAccountView(View):

    def post(self, request, *args, **kwargs):
        address = request.POST.get('paypal_address')
        form = PaypalAccountForm(request.POST)
        form = form.save(commit=False)
        form.user = request.user
        form.save()
        # print(address, form, "----------------form-----------------");
        # if form.is_valid():
        #     form = form.save(commit=False)
        #     form.user = request.user
        #     form.save()
        return JsonResponse({'success': True})
        # else:

        #     if form.errors:
        #         errors_list = [{errors : error} for errors in form.errors for error in form.errors[errors]]

        #     print(errors_list)

        #     return JsonResponse({'errors_dict': form.errors})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class WechatAccountView(View):

    def post(self, request, *args, **kwargs):
        form = WechatAccountForm(request.POST, request.FILES)
        if form.is_valid():
            form = form.save(commit=False)
            form.user = request.user
            form.save()
            return JsonResponse({'success': True})
        # return JsonResponse({'success': True})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class AlipayAccountView(View):

    def post(self, request, *args, **kwargs):
        form = AlipayAccountForm(request.POST, request.FILES)
        if form.is_valid():
            form = form.save(commit=False)
            form.user = request.user
            form.save()
            return JsonResponse({'success': True})
        # return JsonResponse({'success': True})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EditBankAccountView(View):
    template_name = 'authentication/edit_bank_account.html'

    def post(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(BankAccount, pk=pk)
        form = BankAccountForm(request.POST, instance=bank_obj)

        if form.is_valid():
            user_profile = Profile.objects.filter(user=self.request.user)
            if user_profile.exists():
                if  request.POST["account_holder_name"] != user_profile[0].full_name:
                    return JsonResponse({'errors_dict': {'account_holder_name':_('Must be the same as the id name')}})   
            form_data = form.save(commit=False)
            form_data.user = request.user
            form_data.save()

            context ={
                'form': form,
                'success': True
            }
            return render(request, self.template_name, context)
        else:

            context ={
                'form': form
            }
            return render(request, self.template_name, context)

    def get(self, request, *args, **kwargs):

        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(BankAccount, pk=pk)

        form = BankAccountForm(instance=bank_obj)

        context ={
            'form': form
        }

        return render(request, self.template_name, context)

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class RemoveBankAccountView(View):

    def post(self, request, *args, **kwargs):

        id = request.POST.get('pk')

        u = BankAccount.objects.get(pk=id).delete()

        return JsonResponse({'success': True})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class RemoveWechatAccountView(View):

    def post(self, request, *args, **kwargs):

        id = request.POST.get('pk')

        u = WechatAccount.objects.get(pk=id).delete()

        return JsonResponse({'success': True})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class RemoveAlipayAccountView(View):

    def post(self, request, *args, **kwargs):

        id = request.POST.get('pk')

        u = AlipayAccount.objects.get(pk=id).delete()

        return JsonResponse({'success': True})

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EditPaypalAccountView(View):
    template_name = 'authentication/edit_paypal_account.html'

    def post(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(PaypalAccount, pk=pk)
        form = PaypalAccountForm(request.POST, instance=bank_obj)

        if form.is_valid():
            form_data = form.save(commit=False)
            form_data.user = request.user
            form_data.save()

            context ={
                'form': form,
                'success': True
            }
            return render(request, self.template_name, context)
        else:

            context ={
                'form': form
            }
            return render(request, self.template_name, context)

    def get(self, request, *args, **kwargs):

        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(PaypalAccount, pk=pk)

        form = PaypalAccountForm(instance=bank_obj)

        context ={
            'form': form
        }

        return render(request, self.template_name, context)

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EditWechatAccountView(View):
    template_name = 'authentication/edit_wechat_account.html'

    def post(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(WechatAccount, pk=pk)
        form = WechatAccountForm(request.POST, request.FILES,instance=bank_obj)
        if form.is_valid():
            form_data = form.save(commit=False)
            form_data.user = request.user
            form_data.save()

            context ={
                'form': form,
                'success': True
            }
            return render(request, self.template_name, context)
        else:

            context ={
                'form': form
            }
            return render(request, self.template_name, context)

    def get(self, request, *args, **kwargs):

        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(WechatAccount, pk=pk)

        form = WechatAccountForm(instance=bank_obj)

        context ={
            'form': form
        }

        return render(request, self.template_name, context)

@method_decorator(login_required, name='dispatch')
@method_decorator(check_otp, name='dispatch')
@method_decorator(check_2fa, name='dispatch')
class EditAlipayAccountView(View):
    template_name = 'authentication/edit_alipay_account.html'

    def post(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(AlipayAccount, pk=pk)
        form = AlipayAccountForm(request.POST, request.FILES,instance=bank_obj)
        if form.is_valid():
            form_data = form.save(commit=False)
            form_data.user = request.user
            form_data.save()

            context ={
                'form': form,
                'success': True
            }
            return render(request, self.template_name, context)
        else:

            context ={
                'form': form
            }
            return render(request, self.template_name, context)

    def get(self, request, *args, **kwargs):

        pk = self.kwargs['pk']
        bank_obj = get_object_or_404(AlipayAccount, pk=pk)

        form = AlipayAccountForm(instance=bank_obj)

        context ={
            'form': form
        }

        return render(request, self.template_name, context)

class ContactUsView(FormView):
    form_class = ContactUsForm
    template_name = 'authentication/contact_us.html'
    success_url = '.'

    def form_valid(self, form):
        request_object = form.save(commit=False)
        user = User.objects.get(email=form.cleaned_data.get('email'))
        request_object.user = user
        request_object.save()
        messages.success(self.request, _('Your request is successfully registered, Our team will contact soon.'))
        notification = Notification.objects.create(notification='New complaint is registered by {}'.format(user.email))
        for user in User.objects.filter(is_superuser=True):
            NotificationUser.objects.create(notification=notification, user=user)
        return super(ContactUsView, self).form_valid(form)




