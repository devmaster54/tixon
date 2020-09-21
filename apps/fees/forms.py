from django.forms import ModelForm
from django.utils.translation import ugettext_lazy as _

from .models import TransactionFee


class TransactionFeeForm(ModelForm):
	class Meta:
		model = TransactionFee
		fields = ['fee_type', 'rate_type']

