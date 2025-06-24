from functools import wraps
from django.shortcuts          import render
from django.contrib.auth.views import redirect_to_login
from django.http               import HttpResponseForbidden

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

            # all good, go on through
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
