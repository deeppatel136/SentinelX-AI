from django.db import models
from django.contrib.auth.models import User


class ScanHistory(models.Model):

    STATUS_CHOICES = (

        ('Safe', 'Safe'),

        ('Suspicious', 'Suspicious'),

        ('Dangerous', 'Dangerous'),

    )

    SCAN_TYPE_CHOICES = (

        ('URL', 'URL'),

        ('EMAIL', 'EMAIL'),

        ('IMAGE', 'IMAGE'),

        ('FILE', 'FILE'),

    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    # =====================
    # URL Data
    # =====================

    input_data = models.TextField()

    # =====================
    # Email Data
    # =====================

    email_content = models.TextField(
        blank=True,
        null=True
    )

    # =====================
    # Image Data
    # =====================

    image_text = models.TextField(
        blank=True,
        null=True
    )

    image_name = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    # =====================
    # File Data
    # =====================

    file_text = models.TextField(
        blank=True,
        null=True
    )

    file_name = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    # =====================
    # Scan Type
    # =====================

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPE_CHOICES,
        default='URL'
    )

    # =====================
    # Detection Results
    # =====================

    risk_score = models.IntegerField(
        default=0
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Safe'
    )

    analysis_reason = models.TextField(
        blank=True,
        null=True
    )

    # =====================
    # ML Results
    # =====================

    ml_prediction = models.CharField(
        max_length=20,
        blank=True,
        null=True
    )

    ml_confidence = models.FloatField(
        default=0
    )

    # =====================
    # Timestamp
    # =====================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):

        if self.scan_type == 'EMAIL':

            return f"EMAIL - {self.user.username}"

        elif self.scan_type == 'IMAGE':

            return f"IMAGE - {self.user.username}"

        elif self.scan_type == 'FILE':

            return f"FILE - {self.user.username}"

        return self.input_data

from django.db import models
from django.contrib.auth.models import User


class ChatHistory(models.Model):

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    question = models.TextField()

    answer = models.TextField()

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):

        return f"{self.user.username} - {self.question[:50]}"