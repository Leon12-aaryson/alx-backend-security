from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views import View
import json


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """
    Login view with rate limiting.
    - Anonymous users: 5 requests per minute
    - Authenticated users: 10 requests per minute (handled by middleware)
    """
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Username and password are required'
            }, status=400)
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return JsonResponse({
                'message': 'Login successful',
                'user': user.username
            })
        else:
            return JsonResponse({
                'error': 'Invalid credentials'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': 'An error occurred during login'
        }, status=500)


@ratelimit(key='ip', rate='10/m', method='GET', block=True)
@require_http_methods(["GET"])
def admin_dashboard(request):
    """
    Admin dashboard view with rate limiting.
    - 10 requests per minute for authenticated users
    """
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Authentication required'
        }, status=401)
    
    if not request.user.is_staff:
        return JsonResponse({
            'error': 'Staff access required'
        }, status=403)
    
    return JsonResponse({
        'message': 'Welcome to admin dashboard',
        'user': request.user.username
    })


@ratelimit(key='ip', rate='20/m', method='GET', block=True)
@require_http_methods(["GET"])
def public_api(request):
    """
    Public API endpoint with rate limiting.
    - 20 requests per minute for all users
    """
    return JsonResponse({
        'message': 'Public API endpoint',
        'data': 'This is a public API with rate limiting'
    })


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
@require_http_methods(["POST"])
def sensitive_operation(request):
    """
    Sensitive operation with strict rate limiting.
    - 5 requests per minute for all users
    """
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Authentication required'
        }, status=401)
    
    return JsonResponse({
        'message': 'Sensitive operation completed',
        'user': request.user.username
    })


@method_decorator(ratelimit(key='ip', rate='10/m', method='all', block=True), name='dispatch')
class RateLimitedView(View):
    """
    Class-based view with rate limiting.
    - 10 requests per minute for all methods
    """
    
    def get(self, request):
        return JsonResponse({
            'message': 'GET request to rate limited view',
            'method': 'GET'
        })
    
    def post(self, request):
        return JsonResponse({
            'message': 'POST request to rate limited view',
            'method': 'POST'
        })


@login_required
@ratelimit(key='user', rate='15/m', method='GET', block=True)
def user_profile(request):
    """
    User profile view with user-based rate limiting.
    - 15 requests per minute per user
    """
    return JsonResponse({
        'message': 'User profile data',
        'user': request.user.username,
        'email': request.user.email
    })
