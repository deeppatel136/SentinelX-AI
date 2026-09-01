from django.urls import path
from . import views


urlpatterns = [

    # ==========================
    # PUBLIC PAGES
    # ==========================

    path("", views.landing_page, name="landing"),

    path(
        "login/",
        views.login_view,
        name="login"
    ),

    path(
        "register/",
        views.register_view,
        name="register"
    ),


    # ==========================
    # DASHBOARD
    # ==========================

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard"
    ),


    # ==========================
    # URL SCANNER
    # ==========================

    path(
        "scan/",
        views.scan_url,
        name="scan"
    ),


    # ==========================
    # OTHER SCANNERS
    # ==========================

    path(
        "email-scan/",
        views.email_scan,
        name="email_scan"
    ),

    path(
        "image-scan/",
        views.image_scan,
        name="image_scan"
    ),

    path(
        "file-scan/",
        views.file_scan,
        name="file_scan"
    ),

    path(
        "qr-scan/",
        views.qr_scan,
        name="qr_scan"
    ),


    # ==========================
    # SCAN HISTORY
    # ==========================

    path(
        "history/",
        views.history,
        name="history"
    ),


    # ==========================
    # REPORT
    # ==========================

    path(
        "download-report/",
        views.download_report,
        name="download_report"
    ),


    # ==========================
    # AUTHENTICATION
    # ==========================

    path(
        "logout/",
        views.logout_view,
        name="logout"
    ),


    # ==========================
    # AI CHATBOT
    # ==========================

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


    # ==========================
    # HEALTH CHECK
    # ==========================

    path(
        "health/",
        views.health_check,
        name="health_check"
    ),
    
    path(
    "api/scan-activity/",
    views.scan_activity_api,
    name="scan_activity_api"
),
    
path(
        "settings/",
        views.settings_view,
        name="settings"
    ),

 path(
        "help-support/",
        views.help_support,
        name="help_support"
    ),
]