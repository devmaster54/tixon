from django.db import models
from django.contrib.sites.models import Site
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from decimal import Decimal

FEE_TYPE = (
        # ('maker', 'Maker'),
        ('taker', _('Taker')),
        ('withdrawal', _('Withdrawal'))
    )

RATE_TYPE = (
        ('fixed', _('Fixed')),
        ('percentage', _('Percentage'))
    )

LIMIT = (
        ('greater than or equal to', _('Greater Than or Equal To')),
    )

CURRENCY = (
        ('btc','BTC'),
        ('sgd', 'SGD')
    )

def validate_decimal(value):

    try:
        Decimal(value)
    except:
        raise ValidationError(_('Invalid input'))


class MiningFees(models.Model):
    site = models.OneToOneField(Site, on_delete=models.CASCADE)
    mining_fees = models.CharField(max_length=200,default='0.00', validators=[validate_decimal])


class TransactionFee(models.Model):
    currency = models.CharField(max_length=200, choices=CURRENCY)
    fee_type = models.CharField(max_length=200, choices=FEE_TYPE, unique=True)
    rate_type = models.CharField(max_length=200, choices=RATE_TYPE)


class TransactionFeeRange(models.Model):
    transaction_fee = models.ForeignKey('TransactionFee', on_delete=models.CASCADE)
    limit = models.CharField(max_length=200, choices=LIMIT, default='greater than or equal to')
    value = models.CharField(max_length=200, validators=[validate_decimal])
    fees = models.CharField(max_length=200, validators=[validate_decimal])

    class Meta:
        unique_together = ("transaction_fee", "limit", "value")

    def __str__(self):
        return self.value