from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from apps.bitcoin_crypto.models import OrderMatchingHistory
from apps.bitcoin_crypto.utils import calculate_24Hr_time
from django.db.models import Q, Max, Min, Avg, Sum


class BTCSGDExchangeRate(View):

    def get(self, request, *args, **kwargs):

        current, hr24_before = calculate_24Hr_time()

        # calculating last price
        try:
            last_price =  OrderMatchingHistory.objects.all().latest('order_matching_time').matching_price
        except:
            last_price = 0.0
        
        # calculating 24 hr change
        try:
            price_before_24hr = OrderMatchingHistory.objects.filter(order_matching_time__lte=hr24_before).latest('order_matching_time').matching_price
        except:
            price_before_24hr = 0.0            
        try:
            current_price = OrderMatchingHistory.objects.filter(order_matching_time__lte=current).latest('order_matching_time').matching_price
        except:
            current_price = price_before_24hr
        change_24_hr = current_price - price_before_24hr

        # calculating 24 hr heigh
        max_value = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Max('matching_price'))
        high_24_hr = max_value.get('matching_price__max', 0) if max_value.get('matching_price__max', 0) else 0.0

        # calculating 24 hr low
        min_value = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Min('matching_price'))
        low_24_hr = min_value.get('matching_price__min', 0) if min_value.get('matching_price__min', 0) else 0.0

        # calculating 24 hr volume
        price = OrderMatchingHistory.objects.filter(Q(order_matching_time__lte=current) and Q(order_matching_time__gte=hr24_before)).aggregate(Sum('matching_price', field="matching_price * coins_covered"))
        volume_24_hr = price.get('matching_price__sum', 0) if price.get('matching_price__sum', 0) else 0.0

        exchange_data = {
            "lastPrice": last_price,
            "currency": "SGD",
            'short' : 'BTC',
            "long": "Bitcoin",
            "change24hr": change_24_hr,
            "high24hr": high_24_hr,
            "low24hr" : low_24_hr,
            "volume24hr": volume_24_hr
        }
        return JsonResponse(exchange_data)