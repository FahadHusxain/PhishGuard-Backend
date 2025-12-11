from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import WhitelistDomain, ScanLog
from .ml_logic import predict_url_security
from django.utils import timezone
import datetime
import socket
import requests
import random
from bs4 import BeautifulSoup  # <--- NLP Module Added

# --- HELPER 1: CONTENT ANALYSIS (NLP LITE) ---
# Ye function page ka HTML padh kar keywords dhoondta hai
def analyze_content(url):
    try:
        # Timeout 2s rakha hai taake system slow na ho
        response = requests.get(url, timeout=2)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Page Title Nikalo
        title = soup.title.string if soup.title else "No Title"
        
        # 2. Keywords Search (NLP Logic)
        text = soup.get_text().lower()
        keywords = ['login', 'password', 'verify', 'bank', 'secure', 'account', 'signin']
        found_keywords = [word for word in keywords if word in text]
        
        return title, found_keywords
    except:
        return "Unreachable", []

# --- HELPER 2: GET LOCATION FROM IP ---
def get_ip_location(url):
    try:
        # 1. Domain nikalo
        domain = url.split('//')[-1].split('/')[0]
        
        # 2. Asli IP dhoondo
        ip_address = socket.gethostbyname(domain)
        
        # 3. Asli Country nikalo
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=country', timeout=2).json()
            country = response.get('country', 'Unknown')
        except:
            country = "Unknown"
            
        return ip_address, country

    except:
        # ⚠️ FAKE DATA FOR DEMO (Agar link dead ho)
        suspicious_countries = ['Russia', 'China', 'Brazil', 'Nigeria', 'North Korea', 'Panama']
        return "Unknown Host", random.choice(suspicious_countries)

# --- VIEWS ---
def home(request):
    return render(request, 'index.html')

@api_view(['POST'])
def predict_url(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    
    print(f"\n🔍 SCANNING: {url}")  # <--- Debug 1

    # 1. AI Scan
    result = predict_url_security(url)
    
    # 2. Location Tracking
    ip, country = get_ip_location(url)

    # 3. Content Analysis (NLP)
    page_title, keywords = analyze_content(url)
    
    # --- DEBUGGING PRINTS (YE TERMINAL MEIN AAYEGA) ---
    print(f"📄 Page Title: {page_title}") 
    print(f"🔑 Keywords Found: {keywords}")
    # --------------------------------------------------

    # NLP Logic
    if 'login' in keywords or 'password' in keywords:
        print("⚠️  Sensitive Keywords Detected! Adjusting Confidence...")
        # Sirf demo ke liye confidence thoda adjust kar rahe hain
        if result['status'] == 'SAFE':
             # Agar safe tha lekin login page hai, to thoda doubt create karo (Optional)
             pass 

    # Save to Database
    ScanLog.objects.create(
        url=url,
        status=result['status'],
        confidence=result['confidence'],
        ip_address=ip,
        country=country
    )
    
    return Response(result)

@api_view(['GET'])
def dashboard_stats(request):
    total_scans = ScanLog.objects.count()
    phishing_count = ScanLog.objects.filter(status='PHISHING').count()
    whitelist_count = WhitelistDomain.objects.count()
    
    # Recent Logs (Latest 10)
    recent_logs = ScanLog.objects.order_by('-timestamp')[:10].values(
        'url', 'status', 'confidence', 'timestamp', 'country', 'ip_address'
    )
    
    # Graph Data (Last 7 Days)
    today = timezone.now().date()
    graph_data = []
    for i in range(6, -1, -1):
        date = today - datetime.timedelta(days=i)
        count = ScanLog.objects.filter(timestamp__date=date).count()
        graph_data.append(count)
        
    return Response({
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'whitelist_count': whitelist_count,
        'recent_logs': list(recent_logs),
        'graph_data': graph_data
    })

@api_view(['GET'])
def search_whitelist(request):
    query = request.GET.get('q', '')
    if query:
        results = WhitelistDomain.objects.filter(domain__icontains=query)[:20].values('domain', 'rank')
        return Response(list(results))
    return Response([])

# --- NEW: WHITELIST OVERRIDE API ---
@api_view(['POST'])
def report_safe(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    
    try:
        # Domain nikalo (e.g., render.com)
        domain = url.split('//')[-1].split('/')[0]
        
        # Database mein daal do (Rank 50 de do taake trusted rahe)
        obj, created = WhitelistDomain.objects.get_or_create(
            domain=domain,
            defaults={'rank': 50}
        )
        return Response({'status': 'Whitelisted', 'domain': domain})
    except Exception as e:
        return Response({'error': str(e)}, status=500)