from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash, get_user_model
from django.contrib.sessions.models import Session
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.files.base import ContentFile
from django.contrib.auth.forms import PasswordChangeForm
from django.views.decorators.http import require_GET
from django.utils import timezone

from .forms import RegisterForm
from .models import CustomUser, Patient
from .supabase_utils import insert_public_key
from .decorators import role_required

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import base64, os, json, qrcode, secrets, io, logging

activity_logger = logging.getLogger('activity')


def home_redirect(request):
    return redirect('login')


@user_passes_test(lambda u: u.is_superuser)
def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)

            # Get password from form
            temp_password = request.POST.get('password')
            user.set_password(temp_password)

            user.must_change_password = True

            # Optionally assign empty public_key first
            user.public_key = ""
            user.save()

            messages.success(request, "User registered successfully.")
            return redirect('register_success')

    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


def register_success(request):
    return render(request, 'register_success.html')

 
@login_required
def password_change(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keep the user logged in

            # Generate RSA key pair
            key = RSA.generate(2048)
            private_key = key.export_key(pkcs=8)
            public_key_pem = key.publickey().export_key(format='PEM')

            # Save on user model
            user.public_key = public_key_pem.decode()
            user.must_change_password = False
            user.save()

            # Debug logs for your report
            print("[KEYGEN] New RSA key pair generated for user:", user.username)
            print("[KEYGEN] Public Key Preview:")
            print(user.public_key[:120], "...")  # Only print the first 120 chars for preview

            # Push public key upstream
            insert_public_key(user.email, user.role, user.public_key)

            # Write private/public files to media/keys/<username>/
            folder = os.path.join(settings.MEDIA_ROOT, 'keys', user.username)
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, 'private.pem'), 'wb') as f:
                f.write(private_key)
            with open(os.path.join(folder, 'public.pem'), 'wb') as f:
                f.write(public_key_pem)

            messages.success(request, 'Your password (and key pair) have been successfully updated!')
            return redirect('password_change_success')

    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'password_change.html', {'form': form})


@login_required
def password_change_success(request):
    return render(request, 'password_change_success.html', {'role': request.user.role})


def login_view(request):
    if request.method == 'POST':
        print("[DEBUG] POST triggered")

        username = request.POST.get('username')
        password = request.POST.get('password')
        next_url = request.POST.get('next')
        print(f"[DEBUG] username: {username}, next_url: {next_url}")

        user = authenticate(request, username=username, password=password)
        print("[DEBUG] authenticate result:", user)

        if user is not None:
            login(request, user)
            print(f"[DEBUG] Logged in as: {user.username}, Role: {user.role}")
            role = getattr(user, 'role', 'superuser') or 'superuser'
            activity_logger.info(f"[LOGIN SUCCESS] {user.username} ({role}) at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}  from IP {get_client_ip(request)}")

            if user.must_change_password:
                return redirect('password_change')

            if next_url:
                print("[DEBUG] Redirecting to next:", next_url)
                return redirect(next_url)
            
            if user.is_superuser:
                return redirect('/admin/')
            elif user.role == 'doctor':
                return redirect('doctor_dashboard')
            elif user.role == 'nurse':
                return redirect('nurse_dashboard')
            else:
                return redirect('/')
        
        else:
            activity_logger.info(f"[FAILED LOGIN] Attempt for '{username}' at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')} from IP {get_client_ip(request)}")
            messages.error(request, "Invalid username or password.")

    # GET request
    next_param = request.GET.get('next', '')
    print(f"[DEBUG] GET login form, next={next_param}")
    messages.warning(request, "Session expired. Please log in again.")
    return render(request, 'login.html', {'next': next_param})


def logout_view(request):
    if request.user.is_authenticated:
        activity_logger.info(
            f"[LOGOUT] {request.user.username} ({request.user.role}) logged out at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    logout(request)
    return redirect('login')


@csrf_exempt
def qr_code(request):
    # Generate a secure random challenge
    challenge = secrets.token_hex(16)
    session_token = secrets.token_urlsafe(32)

    # Save challenge in session to later verify during scan
    request.session['qr_challenge'] = challenge
    request.session['qr_authenticated'] = False
    request.session['qr_session_token'] = session_token
    request.session.save()
    print("[DEBUG] Incoming session_token from mobile:", session_token)

    # Create QR payload
    data = {
        'challenge': challenge,
        'session_token': session_token
    }

    # Create QR image
    img = qrcode.make(json.dumps(data))
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return HttpResponse(buffer.getvalue(), content_type="image/png")


@csrf_exempt
def validate_qr(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            original_challenge = data.get('original_challenge')
            signed_challenge = data.get('signed_challenge')
            session_token = data.get('session_token')

            user = get_user_model().objects.get(username=username)

            if user.must_change_password:
                return JsonResponse({'success': False, 'message': 'User must change password'})

            if not user.public_key:
                return JsonResponse({'success': False, 'message': 'Public key not found'})

            # Verify signature
            public_key = RSA.import_key(user.public_key.encode('utf-8'))
            h = SHA256.new(original_challenge.encode('utf-8'))
            signature = base64.b64decode(signed_challenge)
            pkcs1_15.new(public_key).verify(h, signature)

            # Find matching session and update it
            now = timezone.now()
            sessions = Session.objects.filter(expire_date__gte=now)

            found = False
            for session in sessions:
                session_data = session.get_decoded()
                if session_data.get('qr_session_token') == session_token:
                    session_data['qr_authenticated'] = True
                    session_data['qr_user_id'] = user.id
                    session_data['qr_user_role'] = user.role
                    session.session_data = Session.objects.encode(session_data)
                    session.save()
                    found = True
                    print(f"[DEBUG] Session matched and updated for {username}")
                    break

            if not found:
                print("[DEBUG] Session token not found")

            return JsonResponse({'success': True, 'message': 'Authentication successful'})
        
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Auth failed: {str(e)}'})
           
        
@require_GET
def qr_status(request):
    if request.session.get('qr_authenticated'):
        user_id = request.session.get('qr_user_id')
        if user_id:
            user = get_user_model().objects.get(id=user_id)
            login(request, user)
            print(f"[DEBUG] Session now logged in as: {user.username}")

            role = user.role
            if role == 'doctor':
                return JsonResponse({'authenticated': True, 'redirect_url': '/doctor/'})
            elif role == 'nurse':
                return JsonResponse({'authenticated': True, 'redirect_url': '/nurse/'})
            else:
                return JsonResponse({'authenticated': True, 'redirect_url': '/'})
    
    return JsonResponse({'authenticated': False})


@login_required
@role_required('doctor')
def doctor_dashboard(request):
    patients = Patient.objects.all()
    print("[DEBUG] Dashboard user:", request.user)
    return render(request, 'doctor_dashboard.html', {'patients': patients})


@login_required
def update_patient(request, patient_id):
    patient = get_object_or_404(Patient, id=patient_id)

    if request.method == 'POST':
        patient.name = request.POST.get('name')
        patient.patient_id = request.POST.get('patient_id')
        patient.email = request.POST.get('email')
        patient.phone_number = request.POST.get('phone_number')
        patient.medical_condition = request.POST.get('medical_condition')
        patient.gender = request.POST.get('gender')
        patient.save()
        activity_logger.info(f"[PATIENT UPDATED] '{patient.name}' (ID: {patient.patient_id}) was updated by {request.user.username} at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}")
        return render(request, 'update_success.html', {"patient": patient})

    return render(request, 'update_patient.html', {'patient': patient})


def update_success(request):
    return render(request, 'update_success.html')


@login_required
def delete_patient(request, patient_id):
    patient = get_object_or_404(Patient, id=patient_id)
    patient.delete()
    activity_logger.info(f"[PATIENT DELETED] '{patient.name}' (ID: {patient.patient_id}) was deleted by {request.user.username} at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}")
    return redirect('doctor_dashboard')


@login_required
@role_required('nurse')
def nurse_dashboard(request):
    patients = Patient.objects.all()
    print("[DEBUG] Dashboard user:", request.user)
    return render(request, 'nurse_dashboard.html', {'patients': patients})


@csrf_exempt
def mobile_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            user = authenticate(username=username, password=password)

            if user:
                # Login success, do not start session, just confirm
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid credentials'}, status=401)

        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    return JsonResponse({'error': 'Only POST allowed'}, status=405)


@csrf_exempt
def download_private_key(request, username):
    if request.method == 'GET':
        # Optional: Add token check here for extra security
        print("[DEBUG] Download request for username:", username)

        user_folder = os.path.join(settings.MEDIA_ROOT, 'keys', username, 'private.pem')
        
        print("[DEBUG] Full key path being checked:", user_folder)

        if os.path.exists(user_folder):
            with open(user_folder, 'rb') as f:
                response = HttpResponse(f.read(), content_type='application/x-pem-file')
                response['Content-Disposition'] = f'attachment; filename={username}_private.pem'
                return response
        return JsonResponse({'error': 'Private key not found'}, status=404)
    return JsonResponse({'error': 'Only GET allowed'}, status=405)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
