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

    url_scans = scans.filter(
        scan_type='URL'
    ).count()

    email_scans = scans.filter(
        scan_type='EMAIL'
    ).count()

    image_scans = scans.filter(
        scan_type='IMAGE'
    ).count()

    file_scans = scans.filter(
        scan_type='FILE'
    ).count()

    dangerous_emails = scans.filter(
        scan_type='EMAIL',
        status='Dangerous'
    ).count()

    recent_scans = scans.order_by(
        '-created_at'
    )[:5]

    context = {

        'total_scans': total_scans,

        'safe_count': safe_count,

        'suspicious_count': suspicious_count,

        'dangerous_count': dangerous_count,

        'phishing_count': phishing_count,

        'url_scans': url_scans,

        'email_scans': email_scans,

        'image_scans': image_scans,

        'file_scans': file_scans,

        'dangerous_emails': dangerous_emails,

        'recent_scans': recent_scans

    }

    return render(
        request,
        'dashboard.html',
        context
    )

@login_required
def scan_url(request):

    if request.method == "POST":

        url = request.POST['url']

        # =====================
        # Rule-Based Detection
        # =====================

        score, status, reasons = analyze_url(
            url
        )

        # =====================
        # ML Detection
        # =====================

        features = extract_features(
            url
        )

        prediction, confidence = predict_url(
            features
        )

        print("=" * 50)
        print("URL:", url)
        print("Rule Status:", status)
        print("Prediction:", prediction)
        print("Confidence:", confidence)
        print("=" * 50)

        if prediction == 1:

            ml_result = "Phishing"

        else:

            ml_result = "Legitimate"

        # =====================
        # AI Security Assistant
        # =====================

        ai_explanation = generate_ai_response(

            scan_type="URL",

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
        # Save Scan History
        # =====================

        ScanHistory.objects.create(

            user=request.user,

            scan_type='URL',

            input_data=url,

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

            'url': url,

            'score': score,

            'status': status,

            'reasons': reasons,

            'ml_prediction': ml_result,

            'ml_confidence': round(
                confidence * 100,
                2
            ),

            'ai_explanation': ai_explanation

        }

        return render(

            request,

            'result.html',

            context

        )

    return render(

        request,

        'scan.html'

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

@login_required
def image_scan(request):

    if request.method == "POST":

        image = request.FILES.get(
            'image'
        )

        if image:

            import os
            import tempfile

            temp_file = tempfile.NamedTemporaryFile(
                delete=False,
                suffix='.jpg'
            )

            for chunk in image.chunks():

                temp_file.write(
                    chunk
                )

            temp_file.close()

            # =====================
            # OCR
            # =====================

            extracted_text = extract_text_from_image(
                temp_file.name
            )

            try:

                os.remove(
                    temp_file.name
                )

            except:

                pass

            # =====================
            # Rule-Based Detection
            # =====================

            score, status, reasons = analyze_email(
                extracted_text
            )

            # =====================
            # Machine Learning
            # =====================

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
            print("Prediction  :", ml_result)
            print("Confidence  :", confidence)
            print("=" * 50)

            # =====================
            # AI Security Assistant
            # =====================

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

            # =====================
            # Save History
            # =====================

            ScanHistory.objects.create(

                user=request.user,

                scan_type='IMAGE',

                input_data='Image Scan',

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

            # =====================
            # Result Context
            # =====================

            context = {

                'image_name': image.name,

                'extracted_text': extracted_text,

                'risk_score': score,

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

                'image_result.html',

                context

            )

    return render(

        request,

        'image_scan.html'

    )

@login_required
def file_scan(request):

    if request.method == "POST":

        uploaded_file = request.FILES.get(
            'file'
        )

        if uploaded_file:

            # =====================
            # Save Temporary File
            # =====================

            extension = os.path.splitext(
                uploaded_file.name
            )[1]

            temp_file = tempfile.NamedTemporaryFile(
                delete=False,
                suffix=extension
            )

            for chunk in uploaded_file.chunks():

                temp_file.write(
                    chunk
                )

            temp_file.close()

            # =====================
            # Extract Text
            # =====================

            extracted_text = extract_text_from_file(
                temp_file.name
            )

            try:

                os.remove(
                    temp_file.name
                )

            except:

                pass

            # =====================
            # Rule-Based Detection
            # =====================

            score, status, reasons = analyze_email(
                extracted_text
            )

            # =====================
            # Machine Learning
            # =====================

            prediction, confidence = predict_email(
                extracted_text
            )

            if prediction == 1:

                ml_result = "Phishing"

            else:

                ml_result = "Legitimate"

            print("=" * 50)
            print("FILE SCAN")
            print("=" * 50)
            print("File :", uploaded_file.name)
            print("Rule Status :", status)
            print("Prediction :", ml_result)
            print("Confidence :", confidence)
            print("=" * 50)

            # =====================
            # AI Security Assistant
            # =====================

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

            print("=" * 80)
            print("AI SECURITY ASSISTANT")
            print(ai_explanation)
            print("=" * 80)

            # =====================
            # Save History
            # =====================

            ScanHistory.objects.create(

                user=request.user,

                scan_type='FILE',

                input_data='File Scan',

                file_name=uploaded_file.name,

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

            # =====================
            # Result Context
            # =====================

            context = {

                'file_name': uploaded_file.name,

                'extracted_text': extracted_text,

                'risk_score': score,

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

                'file_result.html',

                context

            )

    return render(

        request,

        'file_scan.html'

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