from django.contrib import admin
from apps.authentication.models import *

admin.site.register(User)
admin.site.register(AccessLog)
admin.site.register(Profile)
admin.site.register(KYCUpload)
admin.site.register(ComplaintsAndRequest)
