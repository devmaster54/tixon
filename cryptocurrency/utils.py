from django.views.static import serve
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from apps.authentication.models import User


class ProtectServe(LoginRequiredMixin, View):

    def get(self, request, path, document_root=None, show_indexes=False):
        user = User.objects.filter(pk=request.user.pk)
        own_url = user.filter(Q(get_user_details__front_page=path)|Q(get_user_details__back_page=path)|
            Q(get_user_address_details__address_proof=path)|Q(get_user_address_details__photo_selfi=path)).exists()

        if request.user.is_superuser or own_url:
            return serve(request, path, document_root, show_indexes)
        else:
           raise PermissionDenied()