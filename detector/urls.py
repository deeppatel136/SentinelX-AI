from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/', views.scan_url, name='scan'),
    path('history/', views.history, name='history'),
    path('logout/', views.logout_view, name='logout'),
    
    path(
    'download-report/',
    views.download_report,
    name='download_report'
),
    
    path(
    'email-scan/',
    views.email_scan,
    name='email_scan'
),
    
    path(
    'image-scan/',
    views.image_scan,
    name='image_scan'
),
    
path(
    'file-scan/',
    views.file_scan,
    name='file_scan'
),
    
path(
    "chatbot/",
    views.chatbot,
    name="chatbot"
),

path(
    "send-message/",
    views.send_message,
    name="send_message"
),

path(
    "chat/<int:chat_id>/",
    views.chat_detail,
    name="chat_detail"
),

path(
    "delete-chat/<int:chat_id>/",
    views.delete_chat,
    name="delete_chat"
),

path(
    "delete-all-chats/",
    views.delete_all_chats,
    name="delete_all_chats"
),

path("qr-scan/", views.qr_scan, name="qr_scan"),

path("health/", views.health_check, name="health_check"),
]