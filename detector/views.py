from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from .models import ScanHistory
from django.contrib.auth.decorators import login_required
from .phishing_detector import analyze_url
from .feature_extractor import extract_features
from .ml_predictor import predict_url
from .email_ml_detector import predict_email
from django.http import HttpResponse
from .image_detector import extract_text_from_image
from .file_extractor import extract_text_from_file

#from .ai_assistant import generate_ai_response
from .ai_security_assistant import generate_ai_response
from .ml_predictor import predict_url
from .feature_extractor import extract_features

import os
import tempfile
from .file_detector import extract_text_from_file

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer
)

from .email_detector import analyze_email

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


def register_view(request):

    if request.method == "POST":

        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        return redirect('login')

    return render(request, 'register.html')


def login_view(request):

    if request.method == "POST":

        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(
            username=username,
            password=password
        )

        if user:
            login(request, user)
            return redirect('dashboard')

    return render(request, 'login.html')



@login_required
def dashboard(request):

    scans = ScanHistory.objects.filter(
        user=request.user
    )

    # ==========================================
    # Overall Statistics
    # ==========================================

    total_scans = scans.count()

    safe_count = scans.filter(
        status="Safe"
    ).count()

    suspicious_count = scans.filter(
        status="Suspicious"
    ).count()

    dangerous_count = scans.filter(
        status="Dangerous"
    ).count()

    phishing_count = scans.filter(
        ml_prediction="Phishing"
    ).count()

    # ==========================================
    # Scan Type Statistics
    # ==========================================

    url_scans = scans.filter(
        scan_type="URL"
    ).count()

    email_scans = scans.filter(
        scan_type="EMAIL"
    ).count()

    image_scans = scans.filter(
        scan_type="IMAGE"
    ).count()

    file_scans = scans.filter(
        scan_type="FILE"
    ).count()

    qr_scans = scans.filter(
        scan_type="QR"
    ).count()

    # ==========================================
    # Dangerous Scan Statistics
    # ==========================================

    dangerous_urls = scans.filter(
        scan_type="URL",
        status="Dangerous"
    ).count()

    dangerous_emails = scans.filter(
        scan_type="EMAIL",
        status="Dangerous"
    ).count()

    dangerous_images = scans.filter(
        scan_type="IMAGE",
        status="Dangerous"
    ).count()

    dangerous_files = scans.filter(
        scan_type="FILE",
        status="Dangerous"
    ).count()

    dangerous_qr = scans.filter(
        scan_type="QR",
        status="Dangerous"
    ).count()

    # ==========================================
    # Recent Activity
    # ==========================================

    recent_scans = scans.order_by(
        "-created_at"
    )[:5]

    # ==========================================
    # Context
    # ==========================================

    context = {

        # Overall
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "dangerous_count": dangerous_count,
        "phishing_count": phishing_count,

        # Scan Types
        "url_scans": url_scans,
        "email_scans": email_scans,
        "image_scans": image_scans,
        "file_scans": file_scans,
        "qr_scans": qr_scans,

        # Dangerous Statistics
        "dangerous_urls": dangerous_urls,
        "dangerous_emails": dangerous_emails,
        "dangerous_images": dangerous_images,
        "dangerous_files": dangerous_files,
        "dangerous_qr": dangerous_qr,

        # Recent Activity
        "recent_scans": recent_scans,

    }

    return render(

        request,

        "dashboard.html",

        context

    )
from .threat_engine import analyze_threat
@login_required
def scan_url(request):

    if request.method == "POST":

        url = request.POST.get("url", "").strip()

        # ==========================================================
        # 1. RULE-BASED URL DETECTION
        # ==========================================================

        rule_result = analyze_url(url)

        score = rule_result.risk_score
        status = rule_result.status
        reasons = rule_result.indicators

        print("=" * 50)
        print("URL:", url)
        print("Rule Score:", score)
        print("Rule Status:", status)
        print("Rule Indicators:", reasons)
        print("=" * 50)

        # ==========================================================
        # 2. MACHINE LEARNING DETECTION
        # ==========================================================

        features = extract_features(url)

        prediction, confidence = predict_url(features)

        if prediction == 1:

            ml_result = "Phishing"

        else:

            ml_result = "Legitimate"

        ml_confidence = round(
            confidence * 100,
            2
        )

        print("=" * 50)
        print("ML Prediction:", ml_result)
        print("ML Confidence:", ml_confidence)
        print("=" * 50)

        # ==========================================================
        # 3. SENTINELX THREAT ENGINE
        # ==========================================================

        threat_result = analyze_threat(

            scan_type="URL",

            rule_score=score,

            status=status,

            reasons=reasons,

            ml_prediction=ml_result,

            ml_confidence=ml_confidence

        )

        # ==========================================================
        # 4. EXTRACT FINAL THREAT RESULT
        # ==========================================================

        final_score = threat_result["risk_score"]

        final_status = threat_result["verdict"]

        final_reasons = threat_result["indicators"]

        final_severity = threat_result["severity"]

        print("=" * 50)
        print("FINAL THREAT ANALYSIS")
        print("Risk Score:", final_score)
        print("Severity:", final_severity)
        print("Verdict:", final_status)
        print("Indicators:", final_reasons)
        print("=" * 50)

        # ==========================================================
        # 5. AI SECURITY ASSISTANT
        # ==========================================================

        ai_explanation = generate_ai_response(

            scan_type="URL",

            status=final_status,

            risk_score=final_score,

            ml_prediction=ml_result,

            ml_confidence=ml_confidence,

            reasons=final_reasons

        )

        print("=" * 80)
        print("AI SECURITY ASSISTANT")
        print(ai_explanation)
        print("=" * 80)

        # ==========================================================
        # 6. SAVE SCAN HISTORY
        # ==========================================================

        ScanHistory.objects.create(

            user=request.user,

            scan_type="URL",

            input_data=url,

            risk_score=final_score,

            status=final_status,

            analysis_reason="\n".join(
                str(reason)
                for reason in final_reasons
            ),

            ml_prediction=ml_result,

            ml_confidence=ml_confidence

        )

        # ==========================================================
        # 7. RESULT PAGE CONTEXT
        # ==========================================================

        context = {

            "url": url,

            "score": final_score,

            "status": final_status,

            "severity": final_severity,

            "reasons": final_reasons,

            "ml_prediction": ml_result,

            "ml_confidence": ml_confidence,

            "ai_explanation": ai_explanation,

        }

        return render(

            request,

            "result.html",

            context

        )

    # ==============================================================
    # GET REQUEST
    # ==============================================================

    return render(

        request,

        "scan.html"

    )

@login_required
def history(request):

    scans = ScanHistory.objects.filter(
        user=request.user
    )

    # =====================
    # Filters
    # =====================

    scan_type = request.GET.get(
        'scan_type'
    )

    status = request.GET.get(
        'status'
    )

    ml_prediction = request.GET.get(
        'ml_prediction'
    )

    start_date = request.GET.get(
        'start_date'
    )

    end_date = request.GET.get(
        'end_date'
    )

    # =====================
    # Scan Type Filter
    # =====================

    if scan_type:

        scans = scans.filter(
            scan_type=scan_type
        )

    # =====================
    # Status Filter
    # =====================

    if status:

        scans = scans.filter(
            status=status
        )

    # =====================
    # ML Prediction Filter
    # =====================

    if ml_prediction:

        scans = scans.filter(
            ml_prediction=ml_prediction
        )

    # =====================
    # Date Filters
    # =====================

    if start_date:

        scans = scans.filter(
            created_at__date__gte=start_date
        )

    if end_date:

        scans = scans.filter(
            created_at__date__lte=end_date
        )

    # =====================
    # Latest First
    # =====================

    scans = scans.order_by(
        '-created_at'
    )

    context = {

        'scans': scans

    }

    return render(

        request,

        'history.html',

        context

    )




@login_required   
def logout_view(request):

    logout(request)

    return redirect('login')


from django.http import HttpResponse
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime



@login_required
def download_report(request):

    response = HttpResponse(
        content_type='application/pdf'
    )

    response[
        'Content-Disposition'
    ] = 'attachment; filename="phishguard_report.pdf"'

    pdf = SimpleDocTemplate(response)

    elements = []

    styles = getSampleStyleSheet()

    # =====================
    # Get Filtered Data
    # =====================

    scans = ScanHistory.objects.filter(
        user=request.user
    )

    status = request.GET.get(
        'status'
    )

    ml_prediction = request.GET.get(
        'ml_prediction'
    )

    start_date = request.GET.get(
        'start_date'
    )

    end_date = request.GET.get(
        'end_date'
    )

    if status:

        scans = scans.filter(
            status=status
        )

    if ml_prediction:

        scans = scans.filter(
            ml_prediction=ml_prediction
        )

    if start_date:

        scans = scans.filter(
            created_at__date__gte=start_date
        )

    if end_date:

        scans = scans.filter(
            created_at__date__lte=end_date
        )

    scans = scans.order_by(
        '-created_at'
    )

    # =====================
    # Title Section
    # =====================

    title = Paragraph(
        "PHISHGUARD AI",
        styles['Title']
    )

    subtitle = Paragraph(
        "Smart Scam & Phishing Detection Platform",
        styles['Heading2']
    )

    elements.append(title)
    elements.append(subtitle)

    elements.append(
        Spacer(1, 20)
    )

    generated_by = Paragraph(
        f"<b>Generated By:</b> {request.user.username}",
        styles['Normal']
    )

    generated_on = Paragraph(
        f"<b>Generated On:</b> {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        styles['Normal']
    )

    elements.append(generated_by)
    elements.append(generated_on)

    elements.append(
        Spacer(1, 20)
    )

    # =====================
    # Applied Filters
    # =====================

    filter_title = Paragraph(
        "Applied Filters",
        styles['Heading2']
    )

    elements.append(filter_title)

    filter_data = [

        ['Filter', 'Value'],

        [
            'Status',
            status if status else 'All'
        ],

        [
            'ML Prediction',
            ml_prediction if ml_prediction else 'All'
        ],

        [
            'Start Date',
            start_date if start_date else 'Not Specified'
        ],

        [
            'End Date',
            end_date if end_date else 'Not Specified'
        ]

    ]

    filter_table = Table(filter_data)

    filter_table.setStyle(

        TableStyle([

            (
                'BACKGROUND',
                (0,0),
                (-1,0),
                colors.darkgreen
            ),

            (
                'TEXTCOLOR',
                (0,0),
                (-1,0),
                colors.white
            ),

            (
                'GRID',
                (0,0),
                (-1,-1),
                1,
                colors.black
            ),

            (
                'BACKGROUND',
                (0,1),
                (-1,-1),
                colors.lightgreen
            )

        ])

    )

    elements.append(filter_table)

    elements.append(
        Spacer(1, 20)
    )

    # =====================
    # Summary Statistics
    # =====================

    total_scans = scans.count()

    safe_count = scans.filter(
        status='Safe'
    ).count()

    suspicious_count = scans.filter(
        status='Suspicious'
    ).count()

    dangerous_count = scans.filter(
        status='Dangerous'
    ).count()

    phishing_count = scans.filter(
        ml_prediction='Phishing'
    ).count()

    stats_title = Paragraph(
        "Summary Statistics",
        styles['Heading2']
    )

    elements.append(stats_title)

    stats_data = [

        ['Metric', 'Count'],

        ['Total Scans', total_scans],

        ['Safe URLs', safe_count],

        ['Suspicious URLs', suspicious_count],

        ['Dangerous URLs', dangerous_count],

        ['AI Detected Phishing', phishing_count]

    ]

    stats_table = Table(stats_data)

    stats_table.setStyle(

        TableStyle([

            (
                'BACKGROUND',
                (0,0),
                (-1,0),
                colors.darkblue
            ),

            (
                'TEXTCOLOR',
                (0,0),
                (-1,0),
                colors.white
            ),

            (
                'GRID',
                (0,0),
                (-1,-1),
                1,
                colors.black
            ),

            (
                'BACKGROUND',
                (0,1),
                (-1,-1),
                colors.beige
            )

        ])

    )

    elements.append(stats_table)

    elements.append(
        Spacer(1, 20)
    )

    # =====================
    # Detailed Scan Report
    # =====================

    details_title = Paragraph(
        "Detailed Scan Report",
        styles['Heading2']
    )

    elements.append(details_title)

    report_data = [[

        'URL',
        'Score',
        'Status',
        'ML Result',
        'Confidence'

    ]]

    for scan in scans:

        report_data.append([

            scan.input_data[:35],

            str(scan.risk_score),

            scan.status,

            str(scan.ml_prediction),

            f"{scan.ml_confidence}%"

        ])

    report_table = Table(report_data)

    report_table.setStyle(

        TableStyle([

            (
                'BACKGROUND',
                (0,0),
                (-1,0),
                colors.grey
            ),

            (
                'TEXTCOLOR',
                (0,0),
                (-1,0),
                colors.white
            ),

            (
                'GRID',
                (0,0),
                (-1,-1),
                1,
                colors.black
            ),

            (
                'BACKGROUND',
                (0,1),
                (-1,-1),
                colors.whitesmoke
            )

        ])

    )

    elements.append(report_table)

    pdf.build(elements)

    return response

@login_required
def email_scan(request):

    if request.method == "POST":

        email_text = request.POST[
            'email_text'
        ]

        # =====================
        # Rule Based Detection
        # =====================

        score, status, reasons = analyze_email(
            email_text
        )

        # =====================
        # Machine Learning
        # =====================

        prediction, confidence = predict_email(
            email_text
        )

        if prediction == 0:

            ml_result = "Phishing"

        else:

            ml_result = "Legitimate"

        print("=" * 50)
        print("EMAIL SCAN")
        print("=" * 50)
        print(email_text)
        print("Rule Status :", status)
        print("Prediction  :", ml_result)
        print("Confidence  :", confidence)
        print("=" * 50)

        # =====================
        # AI Security Assistant
        # =====================

        ai_explanation = generate_ai_response(

            scan_type="Email",

            status=status,

            risk_score=score,

            ml_prediction=ml_result,

            ml_confidence=round(
                confidence * 100,
                2
            ),

            reasons=reasons

        )

        print("=" * 80)
        print("AI SECURITY ASSISTANT")
        print(ai_explanation)
        print("=" * 80)

        # =====================
        # Save History
        # =====================

        ScanHistory.objects.create(

            user=request.user,

            scan_type='EMAIL',

            email_content=email_text,

            input_data='Email Scan',

            risk_score=score,

            status=status,

            analysis_reason="\n".join(reasons),

            ml_prediction=ml_result,

            ml_confidence=round(
                confidence * 100,
                2
            )

        )

        # =====================
        # Result Context
        # =====================

        context = {

            'email_text': email_text,

            'score': score,

            'status': status,

            'reasons': reasons,

            'ml_prediction': ml_result,

            'ml_confidence': round(
                confidence * 100,
                2
            ),

            'ai_explanation': ai_explanation,

        }

        return render(

            request,

            'email_result.html',

            context

        )

    return render(

        request,

        'email_scan.html'

    )

from .image_validator import ImageValidator


@login_required
def image_scan(request):

    if request.method == "POST":

        image = request.FILES.get("image")

        if image:

            import os
            import tempfile

            temp_file = tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".jpg"
            )

            for chunk in image.chunks():

                temp_file.write(chunk)

            temp_file.close()

            # ===========================================
            # IMAGE VALIDATION
            # ===========================================

            validation = ImageValidator.validate(
                temp_file.name
            )

            if not validation["valid"]:

                try:

                    os.remove(
                        temp_file.name
                    )

                except:

                    pass

                return render(

                    request,

                    "image_result.html",

                    {

                        "image_name": image.name,

                        "validation_failed": True,

                        "error_type": validation["error"],

                        "error_message": validation["message"],

                        "recommendation": validation["recommendation"]

                    }

                )

            # ===========================================
            # OCR
            # ===========================================

            extracted_text = extract_text_from_image(
                temp_file.name
            )

            try:

                os.remove(
                    temp_file.name
                )

            except:

                pass

            # ===========================================
            # RULE BASED DETECTION
            # ===========================================

            score, status, reasons = analyze_email(
                extracted_text
            )

            # ===========================================
            # MACHINE LEARNING
            # ===========================================

            prediction, confidence = predict_email(
                extracted_text
            )

            if prediction == 1:

                ml_result = "Phishing"

            else:

                ml_result = "Legitimate"

            print("=" * 50)
            print("IMAGE SCAN")
            print("=" * 50)
            print("Image :", image.name)
            print("OCR Text:")
            print(extracted_text)
            print("Rule Status :", status)
            print("Prediction :", ml_result)
            print("Confidence :", confidence)
            print("=" * 50)

            # ===========================================
            # AI SECURITY ASSISTANT
            # ===========================================

            ai_explanation = generate_ai_response(

                scan_type="Image",

                status=status,

                risk_score=score,

                ml_prediction=ml_result,

                ml_confidence=round(
                    confidence * 100,
                    2
                ),

                reasons=reasons

            )

            print("=" * 80)
            print("AI SECURITY ASSISTANT")
            print(ai_explanation)
            print("=" * 80)

            # ===========================================
            # SAVE HISTORY
            # ===========================================

            ScanHistory.objects.create(

                user=request.user,

                scan_type="IMAGE",

                input_data="Image Scan",

                image_name=image.name,

                image_text=extracted_text,

                risk_score=score,

                status=status,

                analysis_reason="\n".join(
                    reasons
                ),

                ml_prediction=ml_result,

                ml_confidence=round(
                    confidence * 100,
                    2
                )

            )

            # ===========================================
            # RESULT
            # ===========================================

            context = {

                "image_name": image.name,

                "extracted_text": extracted_text,

                "risk_score": score,

                "status": status,

                "reasons": reasons,

                "ml_prediction": ml_result,

                "ml_confidence": round(
                    confidence * 100,
                    2
                ),

                "ai_explanation": ai_explanation,

                "validation_failed": False,

            }

            return render(

                request,

                "image_result.html",

                context

            )

    return render(

        request,

        "image_scan.html"

    )
    
# ============================================================
# FILE PROCESSING ENGINE
# Used for:
# 1. Normal Files
# 2. Password Protected Files (after authentication)
# ============================================================

def process_file_scan(

    request,

    file_path,

    file_name,

    validation_info=None,

    password=None

):

    import os

    # =====================================
    # File Information
    # =====================================

    file_size = os.path.getsize(file_path)

    file_extension = os.path.splitext(

        file_name

    )[1].lower()

    validation_status = "VALID"

    if validation_info:

        validation_status = validation_info.get(

            "status",

            "VALID"

        )

        file_size = validation_info.get(

            "size",

            file_size

        )

        file_extension = validation_info.get(

            "extension",

            file_extension

        )

    # =====================================
    # Extract Text
    # =====================================

    extracted_text = extract_text_from_file(

        file_path,

        password=password

    )

    # =====================================
    # Rule-Based Detection
    # =====================================

    score, status, reasons = analyze_email(

        extracted_text

    )

    # =====================================
    # Machine Learning
    # =====================================

    prediction, confidence = predict_email(

        extracted_text

    )

    ml_result = (

        "Phishing"

        if prediction == 1

        else "Legitimate"

    )

    # =====================================
    # AI Security Assistant
    # =====================================

    ai_explanation = generate_ai_response(

        scan_type="File",

        status=status,

        risk_score=score,

        ml_prediction=ml_result,

        ml_confidence=round(

            confidence * 100,

            2

        ),

        reasons=reasons

    )

    # =====================================
    # Save Scan History
    # =====================================

    ScanHistory.objects.create(

        user=request.user,

        scan_type="FILE",

        input_data="File Scan",

        file_name=file_name,

        file_text=extracted_text,

        risk_score=score,

        status=status,

        analysis_reason="\n".join(

            reasons

        ),

        ml_prediction=ml_result,

        ml_confidence=round(

            confidence * 100,

            2

        )

    )

    # =====================================
    # Result Context
    # =====================================

    context = {

        "validation_failed": False,

        "file_name": file_name,

        "file_size": file_size,

        "file_extension": file_extension,

        "validation_status": validation_status,

        "extracted_text": extracted_text,

        "risk_score": score,

        "status": status,

        "reasons": reasons,

        "ml_prediction": ml_result,

        "ml_confidence": round(

            confidence * 100,

            2

        ),

        "ai_explanation": ai_explanation

    }

    return render(

        request,

        "file_result.html",

        context

    )
    
from .file_validator import FileValidator    

@login_required
def file_scan(request):

    import os
    import tempfile
    import fitz

    # ==========================================================
    # PASSWORD SUBMISSION
    # ==========================================================

    if request.method == "POST" and request.POST.get("password"):

        password = request.POST.get("password")
        file_path = request.POST.get("file_path")
        file_name = request.POST.get("file_name")

        # ------------------------------------------
        # File Exists?
        # ------------------------------------------

        if not os.path.exists(file_path):

            return render(

                request,

                "file_result.html",

                {

                    "validation_failed": True,

                    "error_type": "FILE_NOT_FOUND",

                    "error_message": "Temporary file no longer exists.",

                    "recommendation": "Please upload the document again."

                }

            )

        # ------------------------------------------
        # Authenticate Password
        # ------------------------------------------

        try:

            pdf = fitz.open(file_path)

            authenticated = pdf.authenticate(password)

            pdf.close()

        except Exception:

            return render(

                request,

                "file_result.html",

                {

                    "validation_failed": True,

                    "error_type": "CORRUPTED_PDF",

                    "error_message": "Unable to open the encrypted document.",

                    "recommendation": "Please upload another PDF."

                }

            )

        # ------------------------------------------
        # Wrong Password
        # ------------------------------------------

        if not authenticated:

            return render(

                request,

                "file_password.html",

                {

                    "file_name": file_name,

                    "file_path": file_path,

                    "error_message": "This document is password protected.",

                    "password_error": "Incorrect password. Please try again."

                }

            )

        # ------------------------------------------
        # Correct Password
        # ------------------------------------------

        validation = {

            "status": "VALID",

            "size": os.path.getsize(file_path),

            "extension": os.path.splitext(file_name)[1].lower()

        }

        try:

            return process_file_scan(

                request=request,

                file_path=file_path,

                file_name=file_name,

                validation_info=validation,

                password=password

            )

        finally:

            try:

                if os.path.exists(file_path):

                    os.remove(file_path)

            except:

                pass

    # ==========================================================
    # FILE UPLOAD
    # ==========================================================

    if request.method == "POST" and request.FILES.get("file"):

        uploaded_file = request.FILES.get("file")

        extension = os.path.splitext(

            uploaded_file.name

        )[1]

        temp_file = tempfile.NamedTemporaryFile(

            delete=False,

            suffix=extension

        )

        for chunk in uploaded_file.chunks():

            temp_file.write(chunk)

        temp_file.close()

        validation = FileValidator.validate(

            temp_file.name

        )

        # ------------------------------------------
        # Password Protected
        # ------------------------------------------

        if validation.get("needs_password"):

            return render(

                request,

                "file_password.html",

                {

                    "file_name": uploaded_file.name,

                    "file_path": temp_file.name,

                    "error_message": validation["message"]

                }

            )

        # ------------------------------------------
        # Other Validation Errors
        # ------------------------------------------

        if not validation["valid"]:

            try:

                os.remove(temp_file.name)

            except:

                pass

            return render(

                request,

                "file_result.html",

                {

                    "validation_failed": True,

                    "file_name": uploaded_file.name,

                    "error_type": validation["error"],

                    "error_message": validation["message"],

                    "recommendation": validation["recommendation"]

                }

            )

        # ------------------------------------------
        # Normal File
        # ------------------------------------------

        try:

            return process_file_scan(

                request=request,

                file_path=temp_file.name,

                file_name=uploaded_file.name,

                validation_info=validation,

                password=None

            )

        finally:

            try:

                if os.path.exists(temp_file.name):

                    os.remove(temp_file.name)

            except:

                pass

    # ==========================================================
    # GET REQUEST
    # ==========================================================

    return render(

        request,

        "file_scan.html"

    )
            
    

        

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .chatbot import generate_chatbot_response
from .models import ChatHistory

@login_required
def chatbot(request):

    chats = ChatHistory.objects.filter(
        user=request.user
    ).order_by(
        "-created_at"
    )

    context = {

        "chats": chats

    }

    return render(

        request,

        "chat.html",

        context

    )
    
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import ChatHistory
from .chatbot import generate_chatbot_response


@login_required
def send_message(request):

    if request.method != "POST":

        return JsonResponse({

            "success": False,

            "error": "Only POST requests are allowed."

        })

    message = request.POST.get(

        "message",

        ""

    ).strip()

    if not message:

        return JsonResponse({

            "success": False,

            "error": "Message cannot be empty."

        })

    try:

        print("=" * 80)
        print("USER MESSAGE")
        print(message)
        print("=" * 80)

        ai_response = generate_chatbot_response(

            message

        )

        print("=" * 80)
        print("AI RESPONSE")
        print(ai_response)
        print("=" * 80)

        ChatHistory.objects.create(

            user=request.user,

            question=message,

            answer=ai_response

        )

        return JsonResponse({

            "success": True,

            "question": message,

            "answer": ai_response

        })

    except Exception as e:

        print("=" * 80)
        print("CHATBOT ERROR")
        print(str(e))
        print("=" * 80)

        return JsonResponse({

            "success": False,

            "error": str(e)

        })
        
from django.shortcuts import get_object_or_404

@login_required
def chat_detail(request, chat_id):

    selected_chat = get_object_or_404(
        ChatHistory,
        id=chat_id,
        user=request.user
    )

    chats = ChatHistory.objects.filter(
        user=request.user
    ).order_by("-created_at")

    context = {

        "selected_chat": selected_chat,

        "chats": chats

    }

    return render(
        request,
        "chat.html",
        context
    )
    
from django.shortcuts import get_object_or_404, redirect

@login_required
def delete_chat(request, chat_id):

    chat = get_object_or_404(

        ChatHistory,

        id=chat_id,

        user=request.user

    )

    chat.delete()

    return redirect("chatbot")

@login_required
def delete_all_chats(request):

    ChatHistory.objects.filter(

        user=request.user

    ).delete()

    return redirect("chatbot")


from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
import os

from .qr_scanner import QRScanner

from .phishing_detector import analyze_url
from .feature_extractor import extract_features
from .ml_predictor import predict_url
from .decision_engine import DecisionEngine

from .upi_analyzer import UPIAnalyzer
from .wifi_analyzer import WiFiAnalyzer
from .email_qr_analyzer import EmailQRAnalyzer

from .ai_qr_assistant import AIQRAssistant

@login_required
def qr_scan(request):

    """
    SentinelX AI
    Universal QR Scanner
    """

    if request.method == "POST":

        image = request.FILES.get("qr_image")

        if not image:

            return render(

                request,

                "qr_scan.html",

                {

                    "success": False,

                    "message": "Please upload a QR image."

                }

            )

        # ==========================================
        # Save Uploaded Image
        # ==========================================

        fs = FileSystemStorage()

        filename = fs.save(

            image.name,

            image

        )

        image_path = fs.path(filename)

        # ==========================================
        # Scan QR
        # ==========================================

        result = QRScanner.scan_qr(image_path)

        if result["success"]:

            # ==========================================
            # Default Values
            # ==========================================

            result.update({

                "risk_score": None,

                "status": None,

                "reasons": [],

                "ml_status": None,

                "ml_confidence": None,

                "final_verdict": None,

                "verdict_color": "secondary",

                "verdict_icon": "ℹ️",

                "verdict_reason": "",

                "ai_report": ""

            })

            # ======================================================
            # WEBSITE QR
            # ======================================================

            if result["qr_type"] == "Website URL":

                url = result["data"]

                # =====================
                # Rule-Based Detection
                # =====================

                rule_result = analyze_url(url)

                score = rule_result.risk_score
                status = rule_result.verdict
                reasons = rule_result.indicators

                features = extract_features(

                    url

                )

                prediction, confidence = predict_url(

                    features

                )

                ml_status = (

                    "Phishing"

                    if prediction == 1

                    else "Legitimate"

                )

                decision = DecisionEngine.final_verdict(

                    status,

                    ml_status,

                    confidence * 100

                )

                result.update({

                    "risk_score": score,

                    "status": status,

                    "reasons": reasons,

                    "ml_status": ml_status,

                    "ml_confidence": round(

                        confidence * 100,

                        2

                    ),

                    "final_verdict": decision["verdict"],

                    "verdict_color": decision["color"],

                    "verdict_icon": decision["icon"],

                    "verdict_reason": decision["reason"]

                })

                result["ai_report"] = AIQRAssistant.generate_report(

                    qr_type="Website URL",

                    verdict=result["final_verdict"],

                    reasons=result["reasons"],

                    extra_info=f"""

Risk Score : {score}

Rule Engine : {status}

Machine Learning : {ml_status}

Confidence : {round(confidence*100,2)}%

URL : {url}

"""

                )
                
                            # ======================================================
            # UPI PAYMENT QR
            # ======================================================

            elif result["qr_type"] == "UPI Payment":

                upi = UPIAnalyzer.analyze(

                    result["data"]

                )

                result.update(upi)

                result["final_verdict"] = upi["upi_risk"]

                result["status"] = upi["upi_risk"]

                result["reasons"] = upi["upi_reasons"]

                if upi["upi_risk"] == "Safe":

                    result["verdict_color"] = "success"

                    result["verdict_icon"] = "🟢"

                else:

                    result["verdict_color"] = "warning"

                    result["verdict_icon"] = "🟡"

                result["ai_report"] = AIQRAssistant.generate_report(

                    qr_type="UPI Payment",

                    verdict=upi["upi_risk"],

                    reasons=upi["upi_reasons"],

                    extra_info=f"""

Receiver : {upi['receiver']}

UPI ID : {upi['upi_id']}

Bank : {upi['bank']}

Amount : {upi['amount']}

Payment Note : {upi['note']}

"""

                )

            # ======================================================
            # WIFI QR
            # ======================================================

            elif result["qr_type"] == "WiFi Configuration":

                wifi = WiFiAnalyzer.analyze(

                    result["data"]

                )

                result.update(wifi)

                result["final_verdict"] = wifi["wifi_risk"]

                result["status"] = wifi["wifi_risk"]

                result["reasons"] = wifi["wifi_reasons"]

                if wifi["wifi_risk"] == "Safe":

                    result["verdict_color"] = "success"

                    result["verdict_icon"] = "🟢"

                elif wifi["wifi_risk"] == "Suspicious":

                    result["verdict_color"] = "warning"

                    result["verdict_icon"] = "🟡"

                else:

                    result["verdict_color"] = "danger"

                    result["verdict_icon"] = "🔴"

                result["ai_report"] = AIQRAssistant.generate_report(

                    qr_type="WiFi Configuration",

                    verdict=wifi["wifi_risk"],

                    reasons=wifi["wifi_reasons"],

                    extra_info=f"""

SSID : {wifi['ssid']}

Encryption : {wifi['encryption']}

Password : {wifi['password']}

"""

                )

            # ======================================================
            # EMAIL QR
            # ======================================================

            elif result["qr_type"] == "Email Address":

                email = EmailQRAnalyzer.analyze(

                    result["data"]

                )

                result.update(email)

                result["final_verdict"] = email["email_risk"]

                result["status"] = email["email_risk"]

                result["reasons"] = email["email_reasons"]

                if email["email_risk"] == "Safe":

                    result["verdict_color"] = "success"

                    result["verdict_icon"] = "🟢"

                else:

                    result["verdict_color"] = "warning"

                    result["verdict_icon"] = "🟡"

                result["ai_report"] = AIQRAssistant.generate_report(

                    qr_type="Email QR",

                    verdict=email["email_risk"],

                    reasons=email["email_reasons"],

                    extra_info=f"""

Recipient : {email['email_to']}

Subject : {email['subject']}

Body : {email['body']}

"""

                )
                
                            # ======================================================
            # UNKNOWN QR TYPE
            # ======================================================

            else:

                result["final_verdict"] = "UNKNOWN"

                result["status"] = "Unknown"

                result["verdict_color"] = "secondary"

                result["verdict_icon"] = "❓"

                result["verdict_reason"] = "Unsupported QR Code type."

                result["ai_report"] = AIQRAssistant.generate_report(

                    qr_type=result["qr_type"],

                    verdict="Unknown",

                    reasons=[],

                    extra_info=result["data"]

                )
        # ======================================================
        # SAVE SCAN HISTORY
        # ======================================================

        try:

            ScanHistory.objects.create(

                user=request.user,

                scan_type="QR",

                input_data=result.get("data", ""),

                risk_score=result.get("risk_score", 0) or 0,

                status=result.get("status", "Unknown"),

                analysis_reason="\n".join(

                    result.get("reasons", [])

                ),

                ml_prediction=result.get(

                    "ml_status",

                    result.get("final_verdict", "N/A")

                ),

                ml_confidence=result.get(

                    "ml_confidence",

                    0

                )

            )

        except Exception as e:

            print("QR History Save Error:", e)

        # ======================================================
        # DELETE TEMP IMAGE
        # ======================================================

        # if os.path.exists(image_path):

        #     os.remove(image_path)

        # ======================================================
        # SELECT RESULT TEMPLATE
        # ======================================================

        template_map = {

            "Website URL": "qr_result_website.html",

            "UPI Payment": "qr_result_upi.html",

            "WiFi Configuration": "qr_result_wifi.html",

            "Email Address": "qr_result_email.html",

        }

        template = template_map.get(

            result.get("qr_type"),

            "qr_result_unknown.html"

        )

        # ======================================================
        # RENDER RESULT
        # ======================================================

        return render(

            request,

            template,

            result

        )

    # ======================================================
    # GET REQUEST
    # ======================================================

    return render(

        request,

        "qr_scan.html"

    )
    
from django.http import JsonResponse


def health_check(request):
    return JsonResponse({"status": "ok"})

def landing_page(request):
    return render(request, "landing.html")

from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta

@login_required
def scan_activity_api(request):
    now = timezone.now()

    activity = []

    for i in range(6, -1, -1):
        day = now - timedelta(days=i)

        start = day.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        end = start + timedelta(days=1)

        count = ScanHistory.objects.filter(
            user=request.user,
            created_at__gte=start,
            created_at__lt=end
        ).count()

        activity.append({
            "date": start.strftime("%a"),
            "count": count
        })

    return JsonResponse({
        "labels": [item["date"] for item in activity],
        "data": [item["count"] for item in activity]
    })
    
# ============================================================
# SETTINGS
# ============================================================

@login_required
def settings_view(request):

    return render(
        request,
        "settings.html"
    )
    
# ==========================================================
# HELP & SUPPORT
# ==========================================================

@login_required
def help_support(request):

    return render(

        request,

        "help_support.html"

    )