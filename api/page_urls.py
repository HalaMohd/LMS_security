from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view),
    path('register/', views.register_page),
    path('login/', views.login_page),
    path('logout/', views.logout_view),
    path('books/', views.books_page),
    path('borrow/', views.borrow_page),
    path('return/', views.return_page),
    path('my-borrows/', views.my_borrows_page),
    path('profile/', views.profile_page),
    path('security/', views.security_page)
]