from django.conf.urls import url

from .views import *

urlpatterns = [
    url(r'^btc-sgd/$', BTCSGDExchangeRate.as_view(), name='btcsgd')
]