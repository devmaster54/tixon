from django.core.management.base import BaseCommand

from apps.authentication.models import User
from apps.bitcoin_crypto.models import SGDWallet


class Command(BaseCommand):

    def handle(self, *args, **options):
        for user in User.objects.all():
            SGDWallet.objects.create(user=user)
