from django.core.management.base import BaseCommand
from django.core.cache import cache
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Block an IP address by adding it to the BlockedIP model'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')
        parser.add_argument('--reason', type=str, help='Reason for blocking the IP')

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options.get('reason', 'No reason provided')
        
        try:
            # Check if IP is already blocked
            if BlockedIP.objects.filter(ip_address=ip_address).exists():
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} is already blocked')
                )
                return
            
            # Create new blocked IP entry
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )
            
            # Clear cache for this IP
            cache_key = f"blocked_ip_{ip_address}"
            cache.delete(cache_key)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully blocked IP {ip_address} (ID: {blocked_ip.id})'
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error blocking IP {ip_address}: {str(e)}')
            )
