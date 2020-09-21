import random

from django.conf import settings
from django.contrib.auth.models import User

from twilio.rest import Client

def send_otp(self, pin, number):
    print(pin)
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body="Your verification code is %s" % pin,
        to=number,
        from_=settings.TWILIO_FROM_NUMBER,
    )
    
    return message.sid

def send_admin_sms(number, message):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

    message = client.messages.create(
        body= message,
        to= number,
        from_=settings.TWILIO_FROM_NUMBER,
    )

def _get_pin(self, length=5):
    """ Return a numeric PIN with length digits """
    return str(random.sample(range(10 ** (length - 1), 10 ** length), 1)[0])


def send_user_sms(self):
    phone_number = self.request.user.phone_number
    pin = _get_pin(self)
    self.request.session['otp'] = pin
    
    try:
        send_otp(self, pin, phone_number)
    except:
        User.objects.filter(id=self.request.user.id).update(phone_number='')
        return {'status': False, "error": "Please Check the Phone Number"}
    return {'status': True}
