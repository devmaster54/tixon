"""cryptocurrency URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include, static
from django.contrib import admin
from django.conf import settings
from django.views.generic.base import TemplateView
from django.contrib.auth.decorators import login_required
from django.views.static import serve
from apps.bitcoin_crypto.views import IndexView, WelcomeView, OtcWelcomeView
from .utils import ProtectServe

from background_task import background

@background()
def check_table():
    # lookup user by id and send them a message
    # user = User.objects.filter()
    print("this is check table scheduler ======== ")


# check_table(repeat=5)

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^crypto/', include('apps.bitcoin_crypto.urls', namespace='coins')),
    url(r'^fees/', include('apps.fees.urls', namespace='fees')),
    url(r'^api/', include('apps.api.urls', namespace='api')),
    url(r'^auth/', include('apps.authentication.urls')),
    url(r'^dashboard/', WelcomeView.as_view(), name='welcome'),
    url(r'^otcdashboard/', OtcWelcomeView.as_view(), name='welcomeotc'),
    url(r'^exchange/', TemplateView.as_view(template_name='theme/exchange.html'), name='exchange'),
    url(r'^$', OtcWelcomeView.as_view(), name='index'),
    # url(r'^%s(?P<path>.*)$' % settings.MEDIA_URL[1:], ProtectServe.as_view(), {'document_root': settings.MEDIA_ROOT}),
    url(r'^i18n/', include('django.conf.urls.i18n')),
]

urlpatterns += static.static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static.static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)