from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.db.models.signals import post_save
from django.dispatch import receiver

import pycountry


COUNTRY_NAME_LIST = sorted([(item.alpha_2, item.name) for item in list(pycountry.countries)], key=lambda country: country[1])

DOCUMENT_TYPE = (
    ('id', _('ID Card')),
    ('pan', _('Pan Card'))
    )

STATUS =(
        ('not-verified', 'Not Verified'),
        ('processing','Processing'),
        ('verified','Verified'),
        ('rejected','Rejected')
    )


class User(AbstractUser):
    phone_number = models.CharField(max_length=20, blank=True, default="", unique=True)
    agree = models.BooleanField(default=False)
    sms_otp = models.BooleanField(default=False)
    google_2fa = models.BooleanField(default=False)
    google_2fa_key = models.CharField(max_length=20, blank=True, null=True)
    change_password_date = models.DateField(default=None, null=True, blank=True)
    kyc_verified = models.CharField(max_length=20, default='not-verified', choices=STATUS)


@receiver(post_save, sender=User)
def save_password(sender, **kwargs):

    instance = kwargs['instance']
    print('saving previous password')
    print(instance)
    if not PreviousPassword.objects.filter(password=instance.password).exists():
        previous_password_count = PreviousPassword.objects.filter(user=instance).count()

        if previous_password_count >= 3:
            oldest_passwords = list(PreviousPassword.objects.filter(user=instance
                ).order_by('id')[:(previous_password_count-2)].values_list("id", flat=True))

            deleted = PreviousPassword.objects.filter(pk__in=oldest_passwords).delete()
            print(deleted)

        PreviousPassword.objects.create(user=instance, password=instance.password)
    else:
        print('password exists in previous')


class AccessLog(models.Model):
    user = models.ForeignKey(User)
    ip = models.CharField(max_length=500, blank=True, default="")
    device = models.CharField(max_length=500, blank=True, default="")
    os = models.CharField(max_length=500, blank=True, default="")
    time = models.DateTimeField(editable=False, default=timezone.now)

    def __str__(self):
        return self.user.username+"-"+self.device


class PreviousPassword(models.Model):
    """
        holding previous and current password hash of all users
    """
    user = models.ForeignKey(User)
    password = models.CharField(max_length=128)


class Profile(models.Model):
    user = models.OneToOneField(User, related_name='get_user_profile')
    full_name = models.CharField(max_length=200, blank=True, default="")

class KYCUpload(models.Model):
    user = models.OneToOneField(User, related_name='get_user_details')
    document_type = models.CharField(max_length=128, choices=DOCUMENT_TYPE)
    document_number = models.CharField(max_length=128, blank=True, default="")
    front_page = models.ImageField()
    back_page = models.ImageField()

    def __str__(self):
        return self.user.first_name


# ACCOUNT_TYPE_LIST = (
#         ('checking', 'Checking'),
#         ('saving', 'Saving')
#     )

class BankAccount(models.Model):
    """
        user bank accounts details for wire tranfer
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    bank_name = models.CharField(max_length=128, verbose_name=_('Bank Name'))
    account_holder_name = models.CharField(max_length=128, verbose_name=_('Your name on your bank account'))
    # account_type = models.CharField(max_length=50, choices=ACCOUNT_TYPE_LIST)
    account_number = models.CharField(max_length=30, verbose_name=_('Bank Account Number'))
    verified = models.BooleanField(default=False)

class PaypalAccount(models.Model):
    """
        user paypal account detail
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    paypal_address = models.CharField(max_length=128, verbose_name=_('Paypal address'))
    verified = models.BooleanField(default=False)

class WechatAccount(models.Model):
    """
        user wechat account detail
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    wechat_account = models.CharField(max_length=128, verbose_name=_('Wechat account'))
    wechat_qr = models.ImageField(upload_to = "static/qr_uploads")
    verified = models.BooleanField(default=False)

class AlipayAccount(models.Model):
    """
        user alipay account detail
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    alipay_number = models.CharField(max_length=128, verbose_name=_('Alipay account'))
    alipay_name = models.CharField(max_length=128, verbose_name=_('Alipay account'))
    alipay_qr = models.ImageField(upload_to = "static/qr_uploads")
    verified = models.BooleanField(default=False)

class ComplaintsAndRequest(models.Model):
    """
        Contact form for users request and complaints
    """
    user = models.ForeignKey(User, related_name='get_the_user_requests')
    subject = models.CharField(max_length=255)
    descrption = models.CharField(max_length=1000)
    is_fixed = models.BooleanField(default=False)
    fixed_by = models.ForeignKey(User, related_name='get_admin_fixed_complaints', null=True, blank=True)

    def __str__(self):
        return self.user.email




