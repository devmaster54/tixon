from apps.bitcoin_crypto.models import Notification

def notification_count(request):

	if request.user.is_authenticated:
		notification_count = Notification.objects.filter(user=request.user, notificationuser__is_readed=False).count()
	else:
		notification_count = 0

	context = {
		'notification_count' : notification_count
	}
	return context


def two_factor_authentication(request):

	if request.user.is_authenticated:
		verified = True
		if request.user.sms_otp:
			verified = request.session.get('otp-verified', False)

		if request.user.google_2fa:
			verified = request.session.get('totp-verified', False)
	else:
		verified = False

	context = {
		'2fa_verified': verified
	}

	return context

