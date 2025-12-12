from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import WhitelistDomain, ScanLog
from .ml_logic import predict_url_security
import socket
import requests

# --- HELPER: Safe IP Lookup ---
def get_ip_location(url):
    try:
        # Domain nikalo
        domain = url.split('//')[-1].split('/')[0].split('?')[0]
        ip_address = socket.gethostbyname(domain)
        
        # Render par kabhi kabhi ye timeout hota hai, isliye chota timeout rakho
        try:
            geo_url = f'http://ip-api.com/json/{ip_address}?fields=country'
            response = requests.get(geo_url, timeout=1) # Sirf 1 second wait karo
            data = response.json()
            return ip_address, data.get('country', 'Unknown')
        except:
            return ip_address, "Unknown"
    except:
        return "0.0.0.0", "Unknown"

# --- API VIEWS ---
def home(request):
    return render(request, 'index.html')

@api_view(['POST'])
def predict_url(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    
    # 1. Whitelist Check
    domain = url.split('//')[-1].split('/')[0]
    whitelist_obj = WhitelistDomain.objects.filter(domain__icontains=domain).first()
    
    if whitelist_obj and whitelist_obj.rank > 0:
        # Whitelist hone par bhi Log Save karna zaroori hai Dashboard ke liye
        ScanLog.objects.create(url=url, status='SAFE', confidence=100, ip_address="Whitelisted", country="Safe Zone")
        return Response({'status': 'SAFE', 'confidence': 100, 'country': 'Whitelisted'})

    # 2. Logic Check
    result = predict_url_security(url)
    
    # 3. Location & Logging (FAIL SAFE BLOCK)
    try:
        ip, country = get_ip_location(url)
        ScanLog.objects.create(
            url=url, 
            status=result['status'], 
            confidence=result['confidence'], 
            ip_address=ip, 
            country=country
        )
    except Exception as e:
        # Agar Database save fail ho, tab bhi User ko result dikhao, crash mat karo
        print(f"Logging Error: {e}")

    return Response(result)

# --- Baki APIs Same Rahengi ---
@api_view(['POST'])
def report_safe(request):
    url = request.data.get('url', '')
    if not url: return Response({'error': 'No URL'}, status=400)
    try:
        domain = url.split('//')[-1].split('/')[0]
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

@api_view(['GET'])
def fix_everything(request):
    return Response({"status": "Admin Fix Tool is Active"})

def analytics_view(request):
    return render(request, 'stats.html')