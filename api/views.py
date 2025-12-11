from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import WhitelistDomain, ScanLog
from .ml_logic import predict_url_security
from django.contrib.auth.models import User
from django.utils import timezone
import datetime
import socket
import requests
from bs4 import BeautifulSoup

# --- HELPER 1: CONTENT ANALYSIS (NLP) ---
def analyze_content(url):
    try:
        response = requests.get(url, timeout=2)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        text = soup.get_text().lower()
        keywords = ['login', 'password', 'verify', 'bank', 'secure', 'account', 'signin']
        found_keywords = [word for word in keywords if word in text]
        return title, found_keywords
    except:
        return "Unreachable", []

# --- HELPER 2: LOCATION ---
def get_ip_location(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        ip_address = socket.gethostbyname(domain)
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=country', timeout=2).json()
            country = response.get('country', 'Unknown')
        except:
            country = "Unknown"
        return ip_address, country
    except:
        return "Unknown Host", "Unknown"

# --- API VIEWS ---
def home(request):
    return render(request, 'index.html')

@api_view(['POST'])
def predict_url(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    
    # 1. Check Whitelist FIRST (Sabse Pehle)
    domain = url.split('//')[-1].split('/')[0]
    whitelist_obj = WhitelistDomain.objects.filter(domain__icontains=domain).first()
    
    if whitelist_obj and whitelist_obj.rank > 0:
        # Agar Whitelist mein hai to SCAN MAT KARO, seedha SAFE bolo
        return Response({'status': 'SAFE', 'confidence': 100, 'country': 'Whitelisted'})

    # 2. AI Scan & Logic
    result = predict_url_security(url)
    ip, country = get_ip_location(url)
    # NLP Analysis (Sirf dikhane ke liye, logic mein interfere nahi karega)
    analyze_content(url) 

    ScanLog.objects.create(url=url, status=result['status'], confidence=result['confidence'], ip_address=ip, country=country)
    return Response(result)

# --- 🔥 YE FUNCTION MISSING THA (Isliye Button kharab tha) ---
@api_view(['POST'])
def report_safe(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    try:
        domain = url.split('//')[-1].split('/')[0]
        # Database mein daal do taake agli baar block na ho
        WhitelistDomain.objects.get_or_create(domain=domain, defaults={'rank': 50})
        return Response({'status': 'Whitelisted'})
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def dashboard_stats(request):
    total_scans = ScanLog.objects.count()
    phishing_count = ScanLog.objects.filter(status='PHISHING').count()
    whitelist_count = WhitelistDomain.objects.count()
    recent_logs = ScanLog.objects.order_by('-timestamp')[:10].values('url', 'status', 'confidence', 'timestamp', 'country')
    return Response({'total_scans': total_scans, 'phishing_count': phishing_count, 'whitelist_count': whitelist_count, 'recent_logs': list(recent_logs), 'graph_data': []})

@api_view(['GET'])
def search_whitelist(request):
    query = request.GET.get('q', '')
    if query:
        results = WhitelistDomain.objects.filter(domain__icontains=query)[:20].values('domain', 'rank')
        return Response(list(results))
    return Response([])

# --- 🛠️ EMERGENCY FIX: CREATE ADMIN & WHITELIST ---
@api_view(['GET'])
def fix_everything(request):
    status_report = {}

    # 1. Admin User Banao
    try:
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', '', 'admin')
            status_report['Admin User'] = "✅ Created (User: admin, Pass: admin)"
        else:
            status_report['Admin User'] = "ℹ️ Already Exists"
    except Exception as e:
        status_report['Admin User'] = f"❌ Error: {str(e)}"

    # 2. Render ko Whitelist Karo
    try:
        domains = ['render.com', 'dashboard.render.com', 'github.com']
        for d in domains:
            WhitelistDomain.objects.get_or_create(domain=d, defaults={'rank': 50})
        status_report['Whitelist'] = "✅ Render & Github Whitelisted!"
    except Exception as e:
        status_report['Whitelist'] = f"❌ Error: {str(e)}"

    return Response(status_report)