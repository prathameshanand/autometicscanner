from django.urls import path
from .views import signup, login_view, logout_view, home

urlpatterns = [
    
    path('home/', home, name='home')
    
]
