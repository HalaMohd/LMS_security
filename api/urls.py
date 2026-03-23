from django.urls import path
from . import views

urlpatterns = [
    path('test/', views.test_view),
    path('register/', views.register_view),
    path('login/', views.login_view),
    path('profile/', views.profile_view),
    path('books/', views.list_books),
    path('borrow/', views.borrow_book),
    path('return/', views.return_book),
    path('my-borrows/', views.my_borrows),
    path('security/', views.security_page),
]
