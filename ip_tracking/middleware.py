import logging
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django_ipgeolocation import Geolocation
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


class IPTrackingMiddleware(MiddlewareMixin):
    """Middleware to track IP addresses and block blacklisted IPs."""
    
    def process_request(self, request):
        """Process incoming request to check for blocked IPs and log request."""
        # Get the real IP address (handles proxies)
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked IP {ip_address} attempted to access {request.path}")
            return HttpResponseForbidden("Access denied: IP address is blocked")
        
        # Log the request
        self.log_request(request, ip_address)
        
        return None
    
    def get_client_ip(self, request):
        """Get the real client IP address, handling proxies and load balancers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_ip_blocked(self, ip_address):
        """Check if the IP address is in the blocked list."""
        # Use cache for better performance
        cache_key = f"blocked_ip_{ip_address}"
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
            # Cache for 1 hour
            cache.set(cache_key, is_blocked, 3600)
        
        return is_blocked
    
    def log_request(self, request, ip_address):
        """Log the request details with geolocation data."""
        try:
            # Check cache for geolocation data
            cache_key = f"geo_{ip_address}"
            geo_data = cache.get(cache_key)
            
            if geo_data is None:
                # Get geolocation data
                geo_data = self.get_geolocation_data(ip_address)
                # Cache for 24 hours
                cache.set(cache_key, geo_data, 86400)
            
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geo_data.get('country'),
                city=geo_data.get('city')
            )
            
            logger.info(f"Request logged: {ip_address} - {request.path} - {geo_data.get('country', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
    
    def get_geolocation_data(self, ip_address):
        """Get geolocation data for an IP address."""
        try:
            # Skip geolocation for private IPs
            if self.is_private_ip(ip_address):
                return {'country': 'Private', 'city': 'Private'}
            
            # Use django-ipgeolocation to get location data
            geolocation = Geolocation()
            geo_data = geolocation.get_geolocation(ip_address)
            
            if geo_data and geo_data.get('status') == 'success':
                return {
                    'country': geo_data.get('country', {}).get('name', 'Unknown'),
                    'city': geo_data.get('city', {}).get('name', 'Unknown')
                }
            else:
                return {'country': 'Unknown', 'city': 'Unknown'}
                
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip_address}: {e}")
            return {'country': 'Unknown', 'city': 'Unknown'}
    
    def is_private_ip(self, ip_address):
        """Check if the IP address is private/local."""
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '::1/128'
        ]
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            for private_range in private_ranges:
                if ip in ipaddress.ip_network(private_range):
                    return True
            return False
        except ValueError:
            return True  # Treat invalid IPs as private
