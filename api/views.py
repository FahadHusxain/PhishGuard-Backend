from rest_framework.decorators import api_view
from rest_framework.response import Response
from .ml_logic import predict_url_security

@api_view(['POST'])
def analyze_url(request):
    # 1. User se URL lo
    data = request.data
    url = data.get('url', '')

    if not url:
        return Response({"error": "No URL provided"}, status=400)

    # 2. Logic wali file ke paas bhejo
    result = predict_url_security(url)

    # 3. Jawab wapis karo (JSON format mein)
    return Response(result)