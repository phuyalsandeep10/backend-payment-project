import requests

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip




def get_location_from_ip(ip):
    try:
        response = requests.get(f'https://ipinfo.io/103.129.135.47/json') # replace the ipaddress{103.129....} with the variable "ip"
        data = response.json()
        city = data.get('city')
        country = data.get('country')
        return f"{city}, {country}" if city else country
    except Exception as e:
        print("IP info error:", e)
        return "Unknown"