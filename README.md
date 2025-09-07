# IP Tracking: Security and Analytics

A comprehensive Django application for IP tracking, security monitoring, and analytics. This system provides IP logging, blacklisting, geolocation tracking, rate limiting, and anomaly detection capabilities.

## Features

### 1. Basic IP Logging Middleware
- Logs IP addresses, timestamps, and request paths
- Handles proxy headers to get real client IPs
- Stores data in `RequestLog` model

### 2. IP Blacklisting
- Blocks malicious IPs using `BlockedIP` model
- Caches blocked IPs for performance
- Management command to add/remove blocked IPs

### 3. IP Geolocation Analytics
- Integrates with django-ipgeolocation
- Tracks country and city data
- Caches geolocation data for 24 hours
- Handles private IPs appropriately

### 4. Rate Limiting
- Uses django-ratelimit for request rate control
- Different limits for authenticated vs anonymous users
- Configurable per-view rate limits
- Supports IP-based and user-based limiting

### 5. Anomaly Detection
- Celery-based background tasks
- Detects suspicious patterns:
  - High request volume (>100 requests/hour)
  - High request rate (>2 requests/minute)
  - Access to sensitive paths
  - Unusual path diversity
  - Rapid geolocation changes
  - Burst patterns
- Automatic cleanup of old logs

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

3. Start Redis (required for Celery and caching):
```bash
redis-server
```

4. Start Celery worker:
```bash
celery -A alx-backend-security worker --loglevel=info
```

5. Start Celery beat (for periodic tasks):
```bash
celery -A alx-backend-security beat --loglevel=info
```

6. Start Django development server:
```bash
python manage.py runserver
```

## Usage

### Blocking IPs
```bash
python manage.py block_ip 192.168.1.100 --reason "Suspicious activity"
```

### Running Anomaly Detection
```bash
# Synchronously
python manage.py run_anomaly_detection

# Asynchronously (requires Celery)
python manage.py run_anomaly_detection --async
```

### Rate Limited Views
The system includes several example views with rate limiting:
- `/login/` - 5 requests/minute
- `/admin/dashboard/` - 10 requests/minute
- `/api/public/` - 20 requests/minute
- `/api/sensitive/` - 5 requests/minute

## Configuration

### Rate Limiting
Configure rate limits in `settings.py`:
```python
RATELIMIT_ANONYMOUS = '5/m'  # 5 requests per minute for anonymous users
RATELIMIT_AUTHENTICATED = '10/m'  # 10 requests per minute for authenticated users
```

### Celery Tasks
Periodic tasks are configured in `settings.py`:
- Anomaly detection: Every hour
- Log cleanup: Daily
- Analytics report: Every hour

## Models

### RequestLog
- `ip_address`: Client IP address
- `timestamp`: Request timestamp
- `path`: Request path
- `country`: Country from geolocation
- `city`: City from geolocation

### BlockedIP
- `ip_address`: Blocked IP address
- `created_at`: When it was blocked
- `reason`: Reason for blocking

### SuspiciousIP
- `ip_address`: Suspicious IP address
- `reason`: Detection reason
- `detected_at`: When it was detected
- `is_active`: Whether the flag is active

## Security Considerations

1. **Privacy Compliance**: The system respects privacy by:
   - Anonymizing private IPs
   - Implementing data retention policies
   - Providing opt-out mechanisms

2. **Performance**: 
   - Uses caching for frequently accessed data
   - Implements batch processing for logs
   - Asynchronous task processing

3. **Ethics**:
   - Avoids blanket blocking of regions
   - Uses fine-grained detection logic
   - Maintains transparency in data usage

## Monitoring

The system provides comprehensive logging and monitoring:
- Request logs with geolocation data
- Suspicious IP detection and flagging
- Rate limiting violations
- System performance metrics

## API Endpoints

- `POST /login/` - Login with rate limiting
- `GET /admin/dashboard/` - Admin dashboard
- `GET /api/public/` - Public API endpoint
- `POST /api/sensitive/` - Sensitive operations
- `GET /profile/` - User profile

## License

This project is part of the ALX Backend Security curriculum.
