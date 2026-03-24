from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import CustomUser, AttackLog, Book, BorrowRecord
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import time
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
import time

def detect_attack(request):
    body = request.body.decode('utf-8', errors='ignore').lower()
    ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    current_time = time.time()

    cache_key = f"api_ratelimit_{ip}"
    timestamps = cache.get(cache_key, [])
    timestamps = [t for t in timestamps if current_time - t < 10]
    timestamps.append(current_time)
    cache.set(cache_key, timestamps, timeout=20)

    if len(timestamps) > 20:
        AttackLog.objects.create(ip_address=ip, attack_type="DoS")
        return "Too many requests (DoS detected)"

    sql_patterns = ["' or 1=1", "union select", "drop table", "--;", "' --", "1=1--"]
    xss_patterns = ["<script>", "</script>", "javascript:", "onerror=", "onload="]

    for pattern in sql_patterns:
        if pattern in body:
            AttackLog.objects.create(ip_address=ip, attack_type="SQL Injection")
            return "SQL Injection detected"

    for pattern in xss_patterns:
        if pattern in body:
            AttackLog.objects.create(ip_address=ip, attack_type="XSS")
            return "XSS attack detected"

    return None



def test_view(request):
    return JsonResponse({"message": "API is working"})

@csrf_exempt
def register_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST method allowed"}, status=405)

    attack = detect_attack(request)
    if attack:
        return JsonResponse({"error": attack}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email", "").strip()
    requested_role = data.get("role")

    if requested_role and requested_role != "student":
        return JsonResponse(
            {"error": "Public registration can only create student accounts"},
            status=403
        )

    if not username or len(username) < 3:
        return JsonResponse({"error": "Username must be at least 3 characters"}, status=400)

    if not password or len(password) < 8:
        return JsonResponse({"error": "Password must be at least 8 characters"}, status=400)

    if CustomUser.objects.filter(username=username).exists():
        return JsonResponse({"error": "Username already taken"}, status=400)

    try:
        user = CustomUser.objects.create_user(
            username=username,
            password=password,
            email=email,
            role="student"
        )
    except Exception:
        return JsonResponse({"error": "Could not create account"}, status=400)

    return JsonResponse({
        "message": "User created successfully",
        "username": user.username
    })


@csrf_exempt
def login_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST method allowed"}, status=405)

    attack = detect_attack(request)
    if attack:
        return JsonResponse({"error": attack}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    username = data.get("username", "")
    password = data.get("password", "")

    user = authenticate(username=username, password=password)

    if user is None:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    refresh = RefreshToken.for_user(user)

    return JsonResponse({
        "refresh": str(refresh),
        "access": str(refresh.access_token),
        "role": user.role
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    return JsonResponse({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def borrow_book(request):
    """Allow a student to borrow an available book."""
    user = request.user

    if user.role != "student":
        return JsonResponse({"error": "Only students can borrow books"}, status=403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    book_id = data.get("book_id")
    if not book_id:
        return JsonResponse({"error": "book_id is required"}, status=400)

    try:
        book = Book.objects.get(id=book_id)
    except Book.DoesNotExist:
        return JsonResponse({"error": "Book not found"}, status=404)

    if not book.available:
        return JsonResponse({"error": "Book is not available"}, status=400)

    # Mark book as unavailable and create borrow record
    book.available = False
    book.save()

    record = BorrowRecord.objects.create(user=user, book=book)

    return JsonResponse({
        "message": f"Successfully borrowed '{book.title}'",
        "borrow_id": record.id,
        "borrowed_at": record.borrowed_at.isoformat()
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def return_book(request):
    """Allow a student to return a borrowed book."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    borrow_id = data.get("borrow_id")

    try:
        record = BorrowRecord.objects.get(id=borrow_id, user=request.user, returned=False)
    except BorrowRecord.DoesNotExist:
        return JsonResponse({"error": "Borrow record not found"}, status=404)

    record.returned = True
    record.save()

    record.book.available = True
    record.book.save()

    return JsonResponse({"message": f"Successfully returned '{record.book.title}'"})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_books(request):
    """List all books. Everyone can see them."""
    books = Book.objects.all().values("id", "title", "author", "available")
    return JsonResponse({"books": list(books)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_borrows(request):
    """Students can view their own borrow history."""
    records = BorrowRecord.objects.filter(user=request.user).select_related("book")
    data = [
        {
            "borrow_id": r.id,
            "book": r.book.title,
            "borrowed_at": r.borrowed_at.isoformat(),
            "returned": r.returned
        }
        for r in records
    ]
    return JsonResponse({"borrows": data})



def home_view(request):
    return render(request, 'home.html')


def register_page(request):
    if request.user.is_authenticated:
        return redirect('/')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        # validation
        if not username:
            messages.error(request, 'Username is required.')
            return redirect('/register/')

        if len(username) < 3:
            messages.error(request, 'Username must be at least 3 characters.')
            return redirect('/register/')

        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return redirect('/register/')

        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters.')
            return redirect('/register/')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return redirect('/register/')

        try:
            user = CustomUser.objects.create_user(
                username=username,
                password=password,
                role="student"
            )
        except Exception:
            messages.error(request, 'Could not create account. Please try again.')
            return redirect('/register/')

        login(request, user)
        messages.success(request, f'Welcome, {username}! Your student account was created.')
        return redirect('/')

    return render(request, 'register.html')



def login_page(request):
    if request.user.is_authenticated:
        return redirect('/')

    attack_warning = None

    if request.method == 'POST':
        # Run attack detection on the raw POST body
        username_input = request.POST.get('username', '')
        password_input = request.POST.get('password', '')
        inspect_text = f"{username_input} {password_input}".lower()

        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        import time
        from django.core.cache import cache

        current_time = time.time()
        cache_key = f"ratelimit_{ip}"
        timestamps = cache.get(cache_key, [])
        timestamps = [t for t in timestamps if current_time - t < 60]
        timestamps.append(current_time)
        cache.set(cache_key, timestamps, timeout=120)


        sql_patterns = ["' or 1=1", "union select", "drop table", "--", "'; drop", "1=1--"]
        xss_patterns = ["<script>", "</script>", "javascript:", "onerror=", "onload="]

        if len(timestamps) > 20:
            AttackLog.objects.create(ip_address=ip, attack_type="DoS")
            attack_warning = "⚠️ DoS Attack Detected — Too many requests from your IP."
        else:
            for pattern in sql_patterns:
                if pattern in inspect_text:
                    AttackLog.objects.create(ip_address=ip, attack_type="SQL Injection")
                    attack_warning = "🛡️ SQL Injection Attempt Detected and Blocked."
                    break

            if not attack_warning:
                for pattern in xss_patterns:
                    if pattern in inspect_text:
                        AttackLog.objects.create(ip_address=ip, attack_type="XSS")
                        attack_warning = "🛡️ XSS Attack Attempt Detected and Blocked."
                        break

        if attack_warning:
            return render(request, 'login.html', {'attack_warning': attack_warning})

        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            messages.success(request, f'Welcome back, {username}!')
            return redirect('/')
        messages.error(request, 'Invalid username or password.')
        return redirect('/login/')

    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('/login/')


def books_page(request):
    books = Book.objects.all()
    return render(request, 'books.html', {'books': books})


@login_required(login_url='/login/')
def borrow_page(request):
    if request.user.role != "student":
        messages.error(request, "Only students can borrow books.")
        return redirect('/books/')
    
    if request.method == 'POST':
        book_id = request.POST.get('book_id')
        try:
            book = Book.objects.get(id=book_id)
        except Book.DoesNotExist:
            messages.error(request, 'Book not found.')
            return redirect('/books/')

        if not book.available:
            messages.error(request, f'"{book.title}" is not available.')
            return redirect('/books/')

        already = BorrowRecord.objects.filter(
            user=request.user, book=book, returned=False
        ).exists()
        if already:
            messages.error(request, 'You already have this book.')
            return redirect('/books/')

        book.available = False
        book.save()
        BorrowRecord.objects.create(user=request.user, book=book)
        messages.success(request, f'You borrowed "{book.title}"!')
        return redirect('/my-borrows/')

    return redirect('/books/')


@login_required(login_url='/login/')
def return_page(request):
    if request.method == 'POST':
        borrow_id = request.POST.get('borrow_id')
        try:
            record = BorrowRecord.objects.get(
                id=borrow_id, user=request.user, returned=False
            )
        except BorrowRecord.DoesNotExist:
            messages.error(request, 'Borrow record not found.')
            return redirect('/my-borrows/')

        record.returned = True
        record.save()
        record.book.available = True
        record.book.save()
        messages.success(request, f'"{record.book.title}" returned successfully.')
        return redirect('/my-borrows/')

    return redirect('/my-borrows/')


@login_required(login_url='/login/')
def my_borrows_page(request):
    records = BorrowRecord.objects.filter(
        user=request.user
    ).select_related('book').order_by('-borrowed_at')
    return render(request, 'my_borrows.html', {'records': records})


@login_required(login_url='/login/')
def profile_page(request):
    attack_logs = []
    if request.user.role in ['admin', 'librarian']:
        attack_logs = AttackLog.objects.all().order_by('-timestamp')[:50]
    return render(request, 'profile.html', {'attack_logs': attack_logs})


@login_required(login_url='/login/')
def security_page(request):
    if request.user.role not in ['admin', 'librarian']:
        messages.error(request, 'You do not have permission to view that page.')
        return redirect('/')
    
    attack_logs = AttackLog.objects.all().order_by('-timestamp')[:50]
    
    stats = {
        'total': AttackLog.objects.count(),
        'sql': AttackLog.objects.filter(attack_type='SQL Injection').count(),
        'xss': AttackLog.objects.filter(attack_type='XSS').count(),
        'dos': AttackLog.objects.filter(attack_type='DoS').count(),
    }
    
    return render(request, 'security.html', {
        'attack_logs': attack_logs,
        'stats': stats,
    })