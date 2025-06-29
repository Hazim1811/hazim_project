from functools                 import wraps
from django.shortcuts          import render
from django.contrib.auth.views import redirect_to_login
from django.http               import JsonResponse, HttpResponseForbidden
from django.conf               import settings


def role_required(role):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # if not logged in, bounce to the login page
            if not request.user.is_authenticated:
                # (you can pass your LOGIN_URL or use the default)
                return redirect_to_login(request.get_full_path())

            # if wrong role, render your 403 template
            if getattr(request.user, 'role', None) != role:
                return render(
                    request,
                    'access_denied.html',
                    {'required_role': role},
                    status=403
                )

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def api_key_required(view_func):
    """
    Decorator for API endpoints that require an X-API-KEY header
    matching SUPABASE_API_KEY in Django settings. Returns 401 JSON
    if unauthorized.
    """
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        client_key = request.headers.get('X-API-KEY')
        if not client_key or client_key != settings.SUPABASE_API_KEY:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped