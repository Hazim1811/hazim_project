from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash, get_user_model
from django.contrib.sessions.models import Session
from django.http import HttpResponse, JsonResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.files.base import ContentFile
from django.contrib.auth.forms import PasswordChangeForm
from django.views.decorators.http import require_GET
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone

from .forms import RegisterForm
from .models import CustomUser, Patient
from .supabase_utils import insert_public_key, sync_patient, delete_patient_record
from .decorators import role_required

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import base64, os, json, qrcode, secrets, io, logging

activity_logger = logging.getLogger('activity')


# Helper decorator to protect mobile/API endpoints with a shared key
def api_key_required(view_func):
    def wrapper(request, *args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if not api_key or api_key != settings.SUPABASE_API_KEY:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


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
@api_key_required
def validate_qr(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    try:
        data = json.loads(request.body)
        user = get_user_model().objects.get(username=data['username'])
        # verify and set session …
        public_key = RSA.import_key(user.public_key.encode())
        h = SHA256.new(data['original_challenge'].encode())
        pkcs1_15.new(public_key).verify(h, base64.b64decode(data['signed_challenge']))
        # mark session …
        for sess in Session.objects.filter(expire_date__gte=timezone.now()):
            d = sess.get_decoded()
            if d.get('qr_session_token') == data['session_token']:
                d.update(qr_authenticated=True, qr_user_id=user.id, qr_user_role=user.role)
                sess.session_data = Session.objects.encode(d); sess.save()
                break
        return JsonResponse({'success': True, 'message': 'Authenticated'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=400)
           
        
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


@staff_member_required
def add_patient(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        medical_condition = request.POST.get('medical_condition')


@login_required
@role_required('doctor')
def update_patient(request, patient_id):
    patient = get_object_or_404(Patient, patient_id=patient_id)

    if request.method == 'POST':
        patient.name = request.POST.get('name')
        patient.email = request.POST.get('email')
        patient.phone_number = request.POST.get('phone_number')
        patient.medical_condition = request.POST.get('medical_condition')
        patient.gender = request.POST.get('gender')
        patient.save()

        success, status_code, response_text = sync_patient({
            "patient_id": patient.patient_id,
            "name": patient.name,
            "email": patient.email,
            "phone_number": patient.phone_number,
            "medical_condition": patient.medical_condition,
            "gender": patient.gender
        })

        if not success:
            activity_logger.warning(
                f"[SUPABASE SYNC FAILED] Sync failed for patient '{patient.name}' ({patient.patient_id}) "
                f"by {request.user.username} | Status: {status_code} | Response: {response_text}"
            )

        activity_logger.info(
            f"[PATIENT UPDATED] '{patient.name}' (ID: {patient.patient_id}) was updated by {request.user.username} "
            f"at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return render(request, 'update_success.html', {"patient": patient})

    return render(request, 'update_patient.html', {'patient': patient})


def update_success(request):
    return render(request, 'update_success.html')


@login_required
@role_required('doctor')
def delete_patient(request, patient_id):
    patient = get_object_or_404(Patient, patient_id=patient_id)
    patient_id_value = patient.patient_id
    patient_name = patient.name
    patient.delete()

    success, status_code, response_text = delete_patient_record(patient_id_value)
    if not success:
        activity_logger.warning(
            f"[SUPABASE SYNC FAILED] Delete failed for patient '{patient_name}' ({patient_id_value}) "
            f"by {request.user.username} | Status: {status_code} | Response: {response_text}"
        )

    activity_logger.info(
        f"[PATIENT DELETED] '{patient_name}' (ID: {patient_id_value}) was deleted by {request.user.username} "
        f"at {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return redirect('doctor_dashboard')


@login_required
@role_required('nurse')
def nurse_dashboard(request):
    patients = Patient.objects.all()
    print("[DEBUG] Dashboard user:", request.user)
    return render(request, 'nurse_dashboard.html', {'patients': patients})


@csrf_exempt
@api_key_required
def mobile_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    data = json.loads(request.body)
    user = authenticate(username=data.get('username'), password=data.get('password'))
    return JsonResponse({'success': bool(user)}, status=(200 if user else 401))


@login_required
def download_private_key(request, username):
    if request.user.username != username:
        raise Http404("Not authorized to download this key.")
    key_path = os.path.join(settings.MEDIA_ROOT, 'keys', username, 'private.pem')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            resp = HttpResponse(f.read(), content_type='application/x-pem-file')
            resp['Content-Disposition'] = f'attachment; filename={username}_private.pem'
            return resp
    return JsonResponse({'error': 'Not found'}, status=404)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
