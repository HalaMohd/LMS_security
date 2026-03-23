from django.contrib import admin
from .models import CustomUser, AttackLog
from .models import Book, BorrowRecord


admin.site.register(CustomUser)
admin.site.register(AttackLog)
admin.site.register(Book)
admin.site.register(BorrowRecord)
# Register your models here.
