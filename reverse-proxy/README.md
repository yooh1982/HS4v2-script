# Reverse Proxy

frp와 유사한 기능을 제공하는 Server-Client 구조의 reverse proxy 프로그램입니다.

## 특징

- **단일 스크립트**: 하나의 Python 파일로 서버와 클라이언트 모두 실행 가능
- **크로스 플랫폼**: Python3가 설치된 모든 OS에서 실행 가능
- **설정 파일 기반**: YAML 설정 파일로 간편한 구성
- **다중 터널 지원**: 여러 포트 포워딩 동시 지원
- **TCP/UDP 지원**: TCP와 UDP 프로토콜 모두 지원
- **자동 재연결**: 클라이언트가 서버와의 연결이 끊어지면 자동으로 재연결
- **비동기 처리**: asyncio를 사용한 고성능 비동기 처리

## 요구사항

- Python 3.7 이상
- PyYAML 라이브러리

## 설치

### 방법 1: Virtual Environment 사용 (권장)

```bash
# 1. 가상 환경 생성
python3 -m venv venv

# 2. 가상 환경 활성화
# macOS/Linux:
source venv/bin/activate

# Windows:
# venv\Scripts\activate

# 3. 의존성 설치
pip install -r requirements.txt

# 4. 가상 환경 비활성화 (작업 완료 후)
deactivate
```

### 방법 2: 시스템 전역 설치

```bash
pip3 install -r requirements.txt
```

## 사용법

### 서버 설정

서버는 공인 IP가 있는 서버에 설치합니다.

1. 설정 파일 생성 (`config.server.yaml`):
```yaml
mode: server

server:
  bind_addr: "0.0.0.0:7000"
  token: "your-secret-token"
```

2. 서버 실행:
```bash
# 가상 환경이 활성화된 상태에서
python3 reverse_proxy.py -c config.server.yaml

# 또는 실행 권한이 있다면
./reverse_proxy.py -c config.server.yaml
```

### 클라이언트 설정

클라이언트는 내부 네트워크의 서버에 설치합니다.

1. 설정 파일 생성 (`config.client.yaml`):
```yaml
mode: client

client:
  server_addr: "your-server.com:7000"
  token: "your-secret-token"
  
  tunnels:
    - name: "web-server"
      type: "tcp"
      remote_port: 8080
      local_addr: "127.0.0.1:3000"
```

2. 클라이언트 실행:
```bash
# 가상 환경이 활성화된 상태에서
python3 reverse_proxy.py -c config.client.yaml
```

## Virtual Environment 상세 가이드

### 가상 환경 생성

```bash
cd reverse-proxy
python3 -m venv venv
```

### 가상 환경 활성화

**macOS/Linux:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

활성화되면 프롬프트에 `(venv)`가 표시됩니다:
```
(venv) user@host:~/reverse-proxy$
```

### 의존성 설치

```bash
# requirements.txt에서 설치
pip install -r requirements.txt

# 또는 개별 설치
pip install PyYAML
```

### 가상 환경 비활성화

```bash
deactivate
```

### 가상 환경 삭제

```bash
# 비활성화 후
rm -rf venv  # macOS/Linux
# 또는
rmdir /s venv  # Windows
```

## 설정 파일 설명

### 서버 설정

- `mode`: `"server"`로 설정
- `server.bind_addr`: 클라이언트 연결을 받을 주소 (예: `"0.0.0.0:7000"`)
- `server.token`: 인증 토큰 (선택사항, 비워두면 인증 없음)

### 클라이언트 설정

- `mode`: `"client"`로 설정
- `client.server_addr`: 서버 주소 (예: `"example.com:7000"`)
- `client.token`: 서버와 동일한 토큰
- `client.tunnels`: 터널 설정 배열
  - `name`: 터널 이름 (고유해야 함)
  - `type`: 터널 타입 (`"tcp"` 또는 `"udp"`)
  - `remote_port`: 서버에서 열 포트
  - `local_addr`: 로컬 서비스 주소 (예: `"127.0.0.1:3000"`)

## 동작 원리

1. 클라이언트가 서버에 연결하고 터널을 등록합니다.
2. 서버가 지정된 포트에서 리스닝을 시작합니다.
3. 외부에서 서버의 포트로 연결 요청이 들어오면:
   - 서버가 클라이언트에게 새 연결 요청을 보냅니다.
   - 클라이언트가 로컬 서비스에 연결합니다.
   - 서버와 클라이언트가 데이터를 양방향으로 프록시합니다.

## 예제

### 웹 서버 포워딩

서버의 8080 포트를 클라이언트의 로컬 3000 포트로 포워딩:

```yaml
tunnels:
  - name: "web"
    type: "tcp"
    remote_port: 8080
    local_addr: "127.0.0.1:3000"
```

외부에서는 `http://your-server.com:8080`으로 접근하면 클라이언트의 `127.0.0.1:3000`으로 연결됩니다.

### DNS 서버 포워딩

UDP를 사용한 DNS 서버 포워딩:

```yaml
tunnels:
  - name: "dns"
    type: "udp"
    remote_port: 53
    local_addr: "127.0.0.1:53"
```

### 여러 터널 동시 사용

```yaml
tunnels:
  - name: "web"
    type: "tcp"
    remote_port: 8080
    local_addr: "127.0.0.1:3000"
  
  - name: "api"
    type: "tcp"
    remote_port: 9000
    local_addr: "127.0.0.1:8080"
  
  - name: "dns"
    type: "udp"
    remote_port: 53
    local_addr: "127.0.0.1:53"
```

## 시스템 서비스로 실행 (Linux)

### systemd 서비스 예제

서버용 (`/etc/systemd/system/reverse-proxy-server.service`):

```ini
[Unit]
Description=Reverse Proxy Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/reverse-proxy
ExecStart=/path/to/venv/bin/python3 /path/to/reverse-proxy/reverse_proxy.py -c /path/to/reverse-proxy/config.server.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

클라이언트용 (`/etc/systemd/system/reverse-proxy-client.service`):

```ini
[Unit]
Description=Reverse Proxy Client
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/reverse-proxy
ExecStart=/path/to/venv/bin/python3 /path/to/reverse-proxy/reverse_proxy.py -c /path/to/reverse-proxy/config.client.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

서비스 시작:

```bash
sudo systemctl daemon-reload
sudo systemctl enable reverse-proxy-server
sudo systemctl start reverse-proxy-server
```

## 문제 해결

### "ModuleNotFoundError: No module named 'yaml'"

PyYAML이 설치되지 않았습니다:

```bash
# 가상 환경 활성화 후
pip install PyYAML

# 또는
pip install -r requirements.txt
```

### "Permission denied"

실행 권한이 없습니다:

```bash
chmod +x reverse_proxy.py
```

### 포트가 이미 사용 중

다른 포트를 사용하거나 기존 프로세스를 종료하세요:

```bash
# 포트 사용 확인
sudo netstat -tulpn | grep :7000

# 프로세스 종료
sudo kill <PID>
```

### 가상 환경이 활성화되지 않음

```bash
# 가상 환경이 있는지 확인
ls -la venv/

# 가상 환경 재생성
python3 -m venv venv
source venv/bin/activate
```

## 라이선스

MIT License
