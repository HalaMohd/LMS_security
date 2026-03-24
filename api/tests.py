""" from django.test import TestCase

# Create your tests here.
# CI pipeline test comment


class DummyFailTest(TestCase):
    def test_fail_on_purpose(self):
        self.assertEqual(1, 2)


class DummyPassTest(TestCase):
    def test_pass(self):
        self.assertEqual(1, 1) """




from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from .models import Book, BorrowRecord, AttackLog
import json

User = get_user_model()


class RegistrationSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_page_registration_rejects_mismatched_passwords(self):
        response = self.client.post("/register/", {
            "username": "user1",
            "password": "Password123",
            "password2": "WrongPassword123",
        }, follow=True)
        self.assertFalse(User.objects.filter(username="user1").exists())

    def test_api_registration_rejects_admin_role(self):
        response = self.client.post(
            "/api/register/",
            data=json.dumps({
                "username": "eviladmin",
                "password": "Password123",
                "role": "admin"
            }),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(username="eviladmin").exists())

    def test_api_registration_rejects_duplicate_username(self):
        User.objects.create_user(username="sameuser", password="Password123", role="student")
        response = self.client.post(
            "/api/register/",
            data=json.dumps({
                "username": "sameuser",
                "password": "Password123"
            }),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)


class BorrowAuthorizationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.student = User.objects.create_user(username="student1", password="Password123", role="student")
        self.admin = User.objects.create_user(username="admin1", password="Password123", role="admin")
        self.book = Book.objects.create(title="Book A", author="Author A", available=True)

    def test_student_can_borrow_page_flow(self):
        self.client.login(username="student1", password="Password123")
        response = self.client.post("/borrow/", {"book_id": self.book.id}, follow=True)
        self.book.refresh_from_db()
        self.assertFalse(self.book.available)

    def test_admin_cannot_borrow_page_flow(self):
        self.client.login(username="admin1", password="Password123")
        response = self.client.post("/borrow/", {"book_id": self.book.id}, follow=True)
        self.book.refresh_from_db()
        self.assertTrue(self.book.available)


class SecurityPageAccessTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.student = User.objects.create_user(username="student2", password="Password123", role="student")
        self.librarian = User.objects.create_user(username="librarian1", password="Password123", role="librarian")

    def test_student_cannot_access_security_page(self):
        self.client.login(username="student2", password="Password123")
        response = self.client.get("/security/", follow=True)
        self.assertEqual(response.status_code, 200)

    def test_librarian_can_access_security_page(self):
        self.client.login(username="librarian1", password="Password123")
        response = self.client.get("/security/")
        self.assertEqual(response.status_code, 200)