import re

from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm, SetPasswordForm, AuthenticationForm
from django.utils.translation import ugettext_lazy as _

from .users import UserModel
from .users import UsernameField
from django.contrib.auth.hashers import check_password
import pyotp
from django.core.exceptions import ValidationError
from apps.authentication.models import Profile, KYCUpload, ComplaintsAndRequest
from django.contrib.auth.hashers import check_password
from .models import PreviousPassword, BankAccount, PaypalAccount, WechatAccount, AlipayAccount, User as auth_user
from .postalcodes import POSTCODES_REGEX

from localflavor.generic.forms import BICFormField

User = UserModel()

def validate_password_strength(username, value):
    """Validates that a password is as least 10 characters long and has at least
    2 digits and 1 Upper case letter.
    """
    min_length = 8

    # try:
    #     username = self.user.username
    # except:
    #     username = self.cleaned_data['username']

    errors = []
    flag = False
    if username.lower().find(value.lower()) != -1:
        errors.append('The password is too similar to the email addess.')
        flag = True

    if len(value) < min_length:
        errors.append(_('Password must be at least {0} characters '
                                'long.').format(min_length))
        flag = True

    # check for 2 digits
    if not any(c.isdigit() for c in value):
        errors.append('Password must contain at least 1 digit.')
        flag = True

    # # check for uppercase letter
    # if not any(c.isupper() for c in value):
    #     errors.append('Password must contain at least 1 uppercase letter.')
    #     flag = True

    # check for uppercase letter
    if not any(c.islower() for c in value):
        errors.append('Password must contain at least 1 lowecase letter.')
        flag = True
    if flag:
        raise ValidationError(errors)
    return value


class RegistrationForm(UserCreationForm):
    """
    Form for registering a new user account.

    """
    required_css_class = 'required'
    email = forms.EmailField(label=_("E-mail"))

    class Meta:
        model = User
        fields = (UsernameField(), "email", "phone_number", "agree",'password1')


    def clean_password1(self):
        try:
            username = self.cleaned_data['username']
        except:
            username = self.data['username']

        return validate_password_strength(username, self.cleaned_data['password1'])

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_("The password does not match the confirm password."))
        return password2
    
    def clean_username(self):
        username = self.cleaned_data.get('username', '').lower()
        if User.objects.filter(**{UsernameField(): username}).exists():
            raise forms.ValidationError(_('A user with that username already exists.'))

        return username

    def clean_email(self):
        """
        Validate that the supplied email address is unique for the
        site.

        """
        if User.objects.filter(email__iexact=self.cleaned_data['email']):
            raise forms.ValidationError(_("This email address is already in use. Please supply a different email address."))
        return self.cleaned_data['email']

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.fields["email"].required = True
        self.fields["phone_number"].required = True
        self.fields["agree"].required = True


class ResendActivationForm(forms.Form):
    required_css_class = 'required'
    email = forms.EmailField(label=_("E-mail"))


class ProfileEditForm(forms.ModelForm):
    
    class Meta:
        model = Profile
        fields = ['full_name']

        error_messages = {
            'full_name': {
                'required': _("Full Name is required"),
            },
        }

    def __init__(self, *args, **kwargs):
        super(ProfileEditForm, self).__init__(*args, **kwargs)
        self.fields["full_name"].required = True

    # def clean_zip_code(self):
    #     zip_code = self.cleaned_data['zip_code']
    #     country_of_residence = self.cleaned_data['country_of_residence']
    #     regex = POSTCODES_REGEX.get(country_of_residence, None)

    #     if regex and not re.match(regex, zip_code):
    #         msg = "Invalid ZIP Code"
    #         raise ValidationError(msg)

    #     return zip_code


class KYCUploadForm(forms.ModelForm):

    class Meta:
        model = KYCUpload
        fields = ['document_type', 'document_number', 'front_page', 'back_page']

        error_messages = {
            'document_type': {
                'required': _("Document Type is required"),
            },
            'document_number': {
                'required': _("Document Number is required"),
            },
            'front_page': {
                'required': _("Front Page is required"),
            },
            'back_page': {
                'required': _("Back Page is required"),
            },
        }

    def __init__(self, *args, **kwargs):
        super(KYCUploadForm, self).__init__(*args, **kwargs)
        self.fields["document_type"].required = True
        self.fields["document_number"].required = True
        self.fields["front_page"].required = True
        self.fields["back_page"].required = True


class Check2FAForm(forms.Form):
    password = forms.CharField(max_length=128, widget=forms.PasswordInput)
    authentication_code = forms.CharField(max_length=128, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):

        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data['password']
        if check_password(password, self.user.password):
            return password
        else:
            raise ValidationError('Invalid Password')

    def clean_authentication_code(self):
        authentication_code = self.cleaned_data['authentication_code']

        totp = pyotp.TOTP(self.user.google_2fa_key)

        if totp.verify(authentication_code):
            return authentication_code
        else:
            raise ValidationError('Invalid Authentication Code')


class PasswordChangeForm(PasswordChangeForm):


    def clean_new_password1(self):
        try:
            username = self.user.username
        except:
            username = self.cleaned_data['username']

        return validate_password_strength(username, self.cleaned_data['new_password1'])

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 == password2:
            passwords_objs = PreviousPassword.objects.filter(user=self.user)
            for password_obj in passwords_objs:
                if check_password(password1, password_obj.password):
                    raise forms.ValidationError(_("New password can not be same as previous three password"))

        return cleaned_data


class CustomSetPasswordForm(SetPasswordForm):

    def clean_new_password1(self):
        username = self.user.username
        return validate_password_strength(username, self.cleaned_data['new_password1'])

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 == password2:
            passwords_objs = PreviousPassword.objects.filter(user=self.user)
            for password_obj in passwords_objs:
                if check_password(password1, password_obj.password):
                    raise forms.ValidationError(_("New password can not be same as previous three password"))

        return cleaned_data


# ACCOUNT_TYPE_LIST = (
#         ('checking', 'Checking'),
#         ('saving', 'Saving')
#     )

class BankAccountForm(forms.ModelForm):
    """
        user back information for feature wire transafer
    """
    # swift_number = BICFormField()
    # account_type = forms.ChoiceField(widget=forms.RadioSelect, choices=ACCOUNT_TYPE_LIST)
    
    class Meta:
        model = BankAccount
        fields = ["bank_name", "account_holder_name", "account_number"] #"account_type",

    def __init__(self, *args, **kwargs):
        super(BankAccountForm, self).__init__(*args, **kwargs)

class PaypalAccountForm(forms.ModelForm):
    """
        user back information for feature wire transafer
    """
    class Meta:
        model = PaypalAccount
        fields = ["paypal_address"]

class WechatAccountForm(forms.ModelForm):
    """
        user back information for feature wire transafer
    """
    class Meta:
        model = WechatAccount
        fields = ["wechat_account", "wechat_qr"]

        error_messages = {
            'wechat_account': {
                'required': _("wechat id is required"),
            },
            'wechat_qr': {
                'required': _(" is required"),
            }
        }

    def __init__(self, *args, **kwargs):
        super(WechatAccountForm, self).__init__(*args, **kwargs)
        self.fields["wechat_account"].required = True
        self.fields["wechat_qr"].required = True

class AlipayAccountForm(forms.ModelForm):

    """docstring for AlipayAccount"""
    class Meta:
        model = AlipayAccount
        fields = ["alipay_number", "alipay_name", "alipay_qr"]

        error_messages = {
            'alipay_account': {
                'required': _("alipay id is required"),
            },
            'alipay_qr': {
                'required': _(" is required"),
            }
        }

    def __init__(self, *args, **kwargs):
        super(AlipayAccountForm, self).__init__(*args, **kwargs)
        self.fields["alipay_number"].required = True
        self.fields["alipay_name"].required = True        
        self.fields["alipay_qr"].required = True        

class ContactUsForm(forms.ModelForm):
    """
        Contact form for users request and complaints
    """
    email = forms.EmailField(max_length=255)
    descrption = forms.CharField(widget=forms.Textarea())

    def clean_subject(self):
        subject = self.cleaned_data.get('subject')
        if subject.strip() is not None:
            return subject
        else:
            raise ValidationError("Subject is mandatory.")

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if auth_user.objects.filter(email=email).exists():
            return email
        else:
            raise ValidationError('Email is not registered with tixon.exchange')

    class Meta:
        model = ComplaintsAndRequest
        fields = ('email', 'subject', 'descrption')