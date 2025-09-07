from django.contrib import admin
from django.urls import path
from ip_tracking import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('api/public/', views.public_api, name='public_api'),
    path('api/sensitive/', views.sensitive_operation, name='sensitive_operation'),
    path('api/rate-limited/', views.RateLimitedView.as_view(), name='rate_limited_view'),
    path('profile/', views.user_profile, name='user_profile'),
]
