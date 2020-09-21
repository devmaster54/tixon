import pytz

from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

class TimezoneMiddleware(MiddlewareMixin):
    def process_request(self, request):
        
        try:
            tzname = request.user.get_user_profile.timezone
        except:
            tzname = 'UTC'

        if tzname:
            timezone.activate(pytz.timezone(tzname))
        else:
            timezone.deactivate()