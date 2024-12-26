import requests
import json
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import os

def requests_retry_session(
    retries=5,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_server_details(api_url):
    response = requests_retry_session().get(api_url, timeout=5)
    data = response.json()
    return data

def main():
    hostname_prefix = input("검색할 서버명을 입력해주세요: ")
    
    full_hostname = f"{hostname_prefix}.cafe24.com"
    server_api = "https://system.hanpda.com/api/web/index.php/system/api/v1/server/detail/"
    api_url = f"{server_api}{full_hostname}"
    server_data = get_server_details(api_url)
    
    # JSON 응답을 출력하여 구조를 이해하기 위해 주석 처리
    # print(json.dumps(server_data, indent=4))
    
    if isinstance(server_data, list):
        server_data = server_data[0] if server_data else {}

    rack_info_list = server_data.get('data', {}).get('server', {}).get('rack_floor_info', 'N/A')
    if isinstance(rack_info_list, list) and len(rack_info_list) >= 6:
        rack_info = f"{rack_info_list[1]}-{rack_info_list[2]}-{rack_info_list[4]}({rack_info_list[5]})"
    else:
        rack_info = 'N/A'
    
    ip_addresses = server_data.get('data', {}).get('server', {}).get('ip_address_type', {}).get('P', [])
    os_info = server_data.get('data', {}).get('server', {}).get('EAV', {}).get('System', {}).get('Os', 'N/A')
    
    ip_addresses_str = ', '.join([ip['name'] for ip in ip_addresses])
    print(f"랙 위치: {rack_info}, OS 타입: {os_info}, IP: {ip_addresses_str}")

if __name__ == "__main__":
    main()
