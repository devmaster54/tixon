from django.contrib import admin

from .models import TransactionFee, TransactionFeeRange

class TransactionFeeRangeInline(admin.TabularInline):
	model = TransactionFeeRange
	extra = 1

class TransactionFeeAdmin(admin.ModelAdmin):
	inlines = [
		TransactionFeeRangeInline
	]

admin.site.register(TransactionFee, TransactionFeeAdmin)
