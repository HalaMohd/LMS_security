from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models


class CustomUserManager(UserManager):
    def create_user(self, username, password=None, **extra_fields):
        extra_fields.setdefault("role", "student")
        return super().create_user(username=username, password=password, **extra_fields)

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields["role"] = "admin"
        return super().create_superuser(username=username, password=password, **extra_fields)


class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('librarian', 'Librarian'),
        ('admin', 'Admin'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.username} ({self.role})"


class AttackLog(models.Model):
    ip_address = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.attack_type}"


class Book(models.Model):
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=200)
    available = models.BooleanField(default=True)

    def __str__(self):
        return self.title


class BorrowRecord(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    borrowed_at = models.DateTimeField(auto_now_add=True)
    returned = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user} borrowed {self.book}"
        