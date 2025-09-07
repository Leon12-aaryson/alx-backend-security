from celery import shared_task
from django.utils import timezone
from django.db import models
from datetime import timedelta
from collections import defaultdict
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    """
    Celery task to detect suspicious IP behavior.
    Runs hourly to analyze request patterns and flag suspicious IPs.
    """
    try:
        logger.info("Starting anomaly detection task")
        
        # Get the last hour's data
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        
        # Analyze request patterns
        ip_stats = analyze_request_patterns(recent_logs)
        
        # Detect suspicious behavior
        suspicious_ips = detect_suspicious_behavior(ip_stats)
        
        # Create SuspiciousIP records
        created_count = 0
        for ip_address, reason in suspicious_ips.items():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason, 'is_active': True}
            )
            if created:
                created_count += 1
                logger.warning(f"Flagged suspicious IP: {ip_address} - {reason}")
        
        logger.info(f"Anomaly detection completed. Flagged {created_count} new suspicious IPs")
        return f"Anomaly detection completed. Flagged {created_count} new suspicious IPs"
        
    except Exception as e:
        logger.error(f"Error in anomaly detection task: {e}")
        raise


def analyze_request_patterns(logs):
    """
    Analyze request patterns to extract statistics per IP.
    """
    ip_stats = defaultdict(lambda: {
        'request_count': 0,
        'unique_paths': set(),
        'sensitive_paths': set(),
        'countries': set(),
        'cities': set(),
        'first_request': None,
        'last_request': None
    })
    
    sensitive_paths = ['/admin/', '/login/', '/api/sensitive/', '/api/admin/']
    
    for log in logs:
        ip = log.ip_address
        stats = ip_stats[ip]
        
        stats['request_count'] += 1
        stats['unique_paths'].add(log.path)
        
        # Check for sensitive paths
        if any(sensitive in log.path for sensitive in sensitive_paths):
            stats['sensitive_paths'].add(log.path)
        
        # Track geolocation diversity
        if log.country:
            stats['countries'].add(log.country)
        if log.city:
            stats['cities'].add(log.city)
        
        # Track time range
        if stats['first_request'] is None or log.timestamp < stats['first_request']:
            stats['first_request'] = log.timestamp
        if stats['last_request'] is None or log.timestamp > stats['last_request']:
            stats['last_request'] = log.timestamp
    
    # Convert sets to counts for easier analysis
    for ip, stats in ip_stats.items():
        stats['unique_path_count'] = len(stats['unique_paths'])
        stats['sensitive_path_count'] = len(stats['sensitive_paths'])
        stats['country_count'] = len(stats['countries'])
        stats['city_count'] = len(stats['cities'])
        
        # Calculate request rate (requests per minute)
        if stats['first_request'] and stats['last_request']:
            time_diff = stats['last_request'] - stats['first_request']
            if time_diff.total_seconds() > 0:
                stats['request_rate'] = stats['request_count'] / (time_diff.total_seconds() / 60)
            else:
                stats['request_rate'] = stats['request_count']
        else:
            stats['request_rate'] = stats['request_count']
    
    return dict(ip_stats)


def detect_suspicious_behavior(ip_stats):
    """
    Detect suspicious behavior patterns and return flagged IPs with reasons.
    """
    suspicious_ips = {}
    
    for ip_address, stats in ip_stats.items():
        reasons = []
        
        # High request volume (more than 100 requests per hour)
        if stats['request_count'] > 100:
            reasons.append(f"High request volume: {stats['request_count']} requests in 1 hour")
        
        # High request rate (more than 2 requests per minute average)
        if stats['request_rate'] > 2:
            reasons.append(f"High request rate: {stats['request_rate']:.2f} requests/minute")
        
        # Accessing sensitive paths
        if stats['sensitive_path_count'] > 0:
            reasons.append(f"Accessing sensitive paths: {list(stats['sensitive_paths'])}")
        
        # Unusual path diversity (accessing many different paths)
        if stats['unique_path_count'] > 50:
            reasons.append(f"Unusual path diversity: {stats['unique_path_count']} unique paths")
        
        # Rapid geolocation changes (multiple countries/cities in short time)
        if stats['country_count'] > 3:
            reasons.append(f"Multiple countries: {list(stats['countries'])}")
        
        if stats['city_count'] > 5:
            reasons.append(f"Multiple cities: {list(stats['cities'])}")
        
        # Burst pattern (many requests in short time)
        if stats['first_request'] and stats['last_request']:
            time_span = stats['last_request'] - stats['first_request']
            if time_span.total_seconds() < 300 and stats['request_count'] > 20:  # 20+ requests in 5 minutes
                reasons.append(f"Burst pattern: {stats['request_count']} requests in {time_span.total_seconds():.0f} seconds")
        
        if reasons:
            suspicious_ips[ip_address] = "; ".join(reasons)
    
    return suspicious_ips


@shared_task
def cleanup_old_logs():
    """
    Cleanup task to remove old request logs to prevent database bloat.
    Keeps logs for 30 days by default.
    """
    try:
        thirty_days_ago = timezone.now() - timedelta(days=30)
        deleted_count, _ = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()
        
        logger.info(f"Cleaned up {deleted_count} old request logs")
        return f"Cleaned up {deleted_count} old request logs"
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {e}")
        raise


@shared_task
def generate_analytics_report():
    """
    Generate analytics report for IP tracking data.
    """
    try:
        # Get data for the last 24 hours
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        recent_logs = RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago)
        
        # Basic statistics
        total_requests = recent_logs.count()
        unique_ips = recent_logs.values('ip_address').distinct().count()
        
        # Top countries
        country_stats = recent_logs.values('country').annotate(
            count=models.Count('id')
        ).order_by('-count')[:10]
        
        # Top paths
        path_stats = recent_logs.values('path').annotate(
            count=models.Count('id')
        ).order_by('-count')[:10]
        
        # Suspicious IPs
        suspicious_count = SuspiciousIP.objects.filter(is_active=True).count()
        
        report = {
            'period': 'Last 24 hours',
            'total_requests': total_requests,
            'unique_ips': unique_ips,
            'top_countries': list(country_stats),
            'top_paths': list(path_stats),
            'suspicious_ips': suspicious_count,
            'generated_at': timezone.now().isoformat()
        }
        
        logger.info(f"Analytics report generated: {total_requests} requests from {unique_ips} IPs")
        return report
        
    except Exception as e:
        logger.error(f"Error generating analytics report: {e}")
        raise
