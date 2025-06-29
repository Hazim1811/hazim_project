from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from Crypto.PublicKey import RSA
import os, json

User = get_user_model()

class UserFlowTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Create a superuser (admin)
        self.admin_user = User.objects.create_superuser(
            username='adminuser',
            email='admin@example.com',
            password='AdminPass123',
            role='admin'
        )

        # Create a regular user
        self.doctor_user = User.objects.create_user(
            username='drjohn',
            email='dr.john@example.com',
            password='TempPass123',
            role='doctor',
            must_change_password=True
        )

    def test_admin_can_access_register(self):
        self.client.login(username='adminuser', password='AdminPass123')
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)

    def test_login_valid_credentials(self):
        response = self.client.post(reverse('login'), {
            'username': 'drjohn',
            'password': 'TempPass123'
        })
        self.assertEqual(response.status_code, 302)  # Should redirect

    def test_login_invalid_credentials(self):
        response = self.client.post(reverse('login'), {
            'username': 'drjohn',
            'password': 'wrongpassword'
        })
        self.assertContains(response, "Invalid username or password.", status_code=200)

    def test_password_change_triggers_key_generation(self):
        self.client.login(username='drjohn', password='TempPass123')
        response = self.client.post(reverse('password_change'), {
            'old_password': 'TempPass123',
            'new_password1': 'NewSecure123',
            'new_password2': 'NewSecure123',
        })
        self.assertRedirects(response, '/change_success/')

        user = User.objects.get(username='drjohn')
        self.assertTrue(user.public_key.startswith("-----BEGIN PUBLIC KEY-----"))

        key_path = os.path.join('media', 'keys', user.username, 'private.pem')
        self.assertTrue(os.path.exists(key_path))

    def test_qr_code_generation(self):
        response = self.client.get(reverse('qr_code'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'image/png')

    def test_private_key_download_success(self):
        # Simulate password change to generate private.pem
        self.client.login(username='drjohn', password='TempPass123')
        self.client.post(reverse('password_change'), {
            'old_password': 'TempPass123',
            'new_password1': 'NewSecure123',
            'new_password2': 'NewSecure123',
        })

        response = self.client.get(f'/private_key/drjohn/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-pem-file')

    def test_private_key_download_not_found(self):
        response = self.client.get('/private_key/unknownuser/')
        self.assertEqual(response.status_code, 302)

    def test_dashboard_access_doctor(self):
        self.doctor_user.must_change_password = False
        self.doctor_user.save()
        self.client.login(username='drjohn', password='TempPass123')
        response = self.client.get(reverse('doctor_dashboard'))
        self.assertContains(response, "Doctor Dashboard", status_code=200)


    def tearDown(self):
        # Clean up generated key files
        folder = os.path.join('media', 'keys', 'drjohn')
        if os.path.exists(folder):
            for file in os.listdir(folder):
                os.remove(os.path.join(folder, file))
            os.rmdir(folder)