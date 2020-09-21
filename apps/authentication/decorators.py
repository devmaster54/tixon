from functools import wraps

from django.urls import reverse
from django.utils.decorators import available_attrs
from django.shortcuts import redirect, render_to_response, render


def check_otp(function):
    def wrap(request, *args, **kwargs):
        if request.session.get('otp-verified') or (not request.user.sms_otp):
            return function(request, *args, **kwargs)
        else:
            return redirect(reverse('check_otp'))
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap


def check_2fa(function):
    def wrap(request, *args, **kwargs):
        
        if request.session.get('totp-verified') or (not request.user.google_2fa):
            return function(request, *args, **kwargs)
        else:
            return redirect(reverse('verify_2fa'))
            
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap
