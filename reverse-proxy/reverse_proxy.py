#!/usr/bin/env python3
"""
Reverse Proxy - frp와 유사한 기능을 제공하는 Server-Client 구조의 reverse proxy

요구사항: Python 3.6 이상
"""

import argparse
import asyncio
import logging
import os
import signal
import struct
import sys
from typing import Dict, Optional, Tuple
import yaml

# Python 버전 확인
if sys.version_info < (3, 6):
    print("Python 3.6 이상이 필요합니다.")
    sys.exit(1)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 메시지 타입
MSG_TYPE_NEW_TUNNEL = 1
MSG_TYPE_CLOSE_TUNNEL = 2
MSG_TYPE_DATA = 3
MSG_TYPE_SUCCESS = 4
MSG_TYPE_ERROR = 5
MSG_TYPE_NEW_CONN = 6
MSG_TYPE_CONN_CLOSED = 7


class Config:
    """설정 파일 관리"""
    
    def __init__(self, path: str):
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        self.mode = data.get('mode')
        if self.mode not in ['server', 'client']:
            raise ValueError("mode는 'server' 또는 'client'여야 합니다")
        
        if self.mode == 'server':
            server_config = data.get('server', {})
            self.server = ServerConfig(
                bind_addr=server_config.get('bind_addr', '0.0.0.0:7000'),
                token=server_config.get('token', '')
            )
        else:
            client_config = data.get('client', {})
            if not client_config.get('server_addr'):
                raise ValueError("client.server_addr이 필요합니다")
            
            tunnels = []
            for tunnel_data in client_config.get('tunnels', []):
                tunnels.append(TunnelConfig(
                    name=tunnel_data['name'],
                    type=tunnel_data['type'],
                    remote_port=tunnel_data['remote_port'],
                    local_addr=tunnel_data['local_addr']
                ))
            
            if not tunnels:
                raise ValueError("최소 하나의 터널 설정이 필요합니다")
            
            self.client = ClientConfig(
                server_addr=client_config['server_addr'],
                token=client_config.get('token', ''),
                tunnels=tunnels
            )


class ServerConfig:
    def __init__(self, bind_addr: str, token: str):
        self.bind_addr = bind_addr
        self.token = token


class ClientConfig:
    def __init__(self, server_addr: str, token: str, tunnels: list):
        self.server_addr = server_addr
        self.token = token
        self.tunnels = tunnels


class TunnelConfig:
    def __init__(self, name: str, type: str, remote_port: int, local_addr: str):
        self.name = name
        self.type = type
        self.remote_port = remote_port
        self.local_addr = local_addr


class Protocol:
    """프로토콜 처리"""
    
    @staticmethod
    async def read_message(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
        """메시지 읽기"""
        msg_type = (await reader.readexactly(1))[0]
        length = struct.unpack('>I', await reader.readexactly(4))[0]
        data = await reader.readexactly(length) if length > 0 else b''
        return msg_type, data
    
    @staticmethod
    async def write_message(writer: asyncio.StreamWriter, msg_type: int, data: bytes):
        """메시지 쓰기"""
        writer.write(bytes([msg_type]))
        writer.write(struct.pack('>I', len(data)))
        if data:
            writer.write(data)
        await writer.drain()
    
    @staticmethod
    def pack_string(s: str) -> bytes:
        """문자열 패킹"""
        s_bytes = s.encode('utf-8')
        return struct.pack('>H', len(s_bytes)) + s_bytes
    
    @staticmethod
    def unpack_string(data: bytes, offset: int = 0) -> Tuple[str, int]:
        """문자열 언패킹"""
        length = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        s = data[offset:offset+length].decode('utf-8')
        return s, offset + length
    
    @staticmethod
    def pack_uint32(n: int) -> bytes:
        """uint32 패킹"""
        return struct.pack('>I', n)
    
    @staticmethod
    def unpack_uint32(data: bytes, offset: int = 0) -> Tuple[int, int]:
        """uint32 언패킹"""
        n = struct.unpack('>I', data[offset:offset+4])[0]
        return n, offset + 4


class Server:
    """서버 클래스"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.sessions: Dict[str, 'Session'] = {}
        self.tunnels: Dict[int, 'Tunnel'] = {}
        self.conn_counter = 0
    
    async def start(self):
        """서버 시작"""
        host, port = self.config.bind_addr.rsplit(':', 1)
        port = int(port)
        
        asyncio_server = await asyncio.start_server(
            self.handle_connection,
            host,
            port
        )
        
        logger.info(f"서버가 {self.config.bind_addr}에서 리스닝 중입니다...")
        
        # Python 3.6 호환성을 위해 async with 대신 직접 사용
        try:
            await asyncio_server.serve_forever()
        finally:
            asyncio_server.close()
            await asyncio_server.wait_closed()
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """클라이언트 연결 처리"""
        remote_addr = writer.get_extra_info('peername')
        logger.info(f"새 클라이언트 연결: {remote_addr}")
        
        session_id = None
        try:
            # 인증
            if not await self.authenticate(reader, writer):
                logger.warning(f"인증 실패: {remote_addr}")
                return
            
            # 세션 생성
            session_id = self.generate_session_id()
            session = Session(session_id, reader, writer)
            self.sessions[session_id] = session
            
            logger.info(f"세션 생성: {session_id} (클라이언트: {remote_addr})")
            
            # 메시지 루프
            while True:
                try:
                    msg_type, data = await Protocol.read_message(reader)
                    
                    if msg_type == MSG_TYPE_NEW_TUNNEL:
                        await self.handle_new_tunnel(session, data)
                    elif msg_type == MSG_TYPE_CLOSE_TUNNEL:
                        await self.handle_close_tunnel(session, data)
                    elif msg_type == MSG_TYPE_DATA:
                        await self.handle_tunnel_data(session, data)
                    elif msg_type == MSG_TYPE_CONN_CLOSED:
                        await self.handle_conn_closed(session, data)
                    else:
                        logger.warning(f"알 수 없는 메시지 타입: {msg_type}")
                except asyncio.IncompleteReadError:
                    break
                except Exception as e:
                    logger.error(f"메시지 처리 오류: {e}")
                    break
        except Exception as e:
            logger.error(f"연결 처리 오류: {e}")
        finally:
            # 세션 정리
            if session_id and session_id in self.sessions:
                session = self.sessions[session_id]
                for tunnel in list(session.tunnels.values()):
                    await tunnel.close()
                del self.sessions[session_id]
            
            writer.close()
            await writer.wait_closed()
            if session_id:
                logger.info(f"세션 종료: {session_id}")
    
    async def authenticate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """인증 처리"""
        if not self.config.token:
            return True
        
        token_length = struct.unpack('>H', await reader.readexactly(2))[0]
        token = (await reader.readexactly(token_length)).decode('utf-8')
        
        return token == self.config.token
    
    async def handle_new_tunnel(self, session: 'Session', data: bytes):
        """새 터널 생성 요청 처리"""
        offset = 0
        name, offset = Protocol.unpack_string(data, offset)
        tunnel_type, offset = Protocol.unpack_string(data, offset)
        remote_port = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        local_addr, offset = Protocol.unpack_string(data, offset)
        
        logger.info(f"터널 생성 요청: {name} (타입: {tunnel_type}, 원격 포트: {remote_port}, 로컬: {local_addr})")
        
        tunnel = Tunnel(name, tunnel_type, remote_port, local_addr, session, self)
        
        try:
            await tunnel.start()
            session.tunnels[name] = tunnel
            self.tunnels[remote_port] = tunnel
            
            await Protocol.write_message(session.writer, MSG_TYPE_SUCCESS, Protocol.pack_string("터널 생성 성공"))
        except Exception as e:
            logger.error(f"터널 시작 실패: {e}")
            error_msg = Protocol.pack_string(f"터널 시작 실패: {str(e)}")
            await Protocol.write_message(session.writer, MSG_TYPE_ERROR, error_msg)
    
    async def handle_close_tunnel(self, session: 'Session', data: bytes):
        """터널 종료 요청 처리"""
        name, _ = Protocol.unpack_string(data)
        
        if name in session.tunnels:
            tunnel = session.tunnels[name]
            del session.tunnels[name]
            
            if tunnel.remote_port in self.tunnels:
                del self.tunnels[tunnel.remote_port]
            
            await tunnel.close()
            logger.info(f"터널 종료: {name}")
    
    async def handle_tunnel_data(self, session: 'Session', data: bytes):
        """터널 데이터 처리"""
        offset = 0
        tunnel_name, offset = Protocol.unpack_string(data, offset)
        conn_id, offset = Protocol.unpack_uint32(data, offset)
        
        # 데이터 길이 읽기
        data_length, offset = Protocol.unpack_uint32(data, offset)
        tunnel_data = data[offset:offset+data_length]
        
        if tunnel_name not in session.tunnels:
            logger.warning(f"터널을 찾을 수 없음: {tunnel_name}")
            return
        
        tunnel = session.tunnels[tunnel_name]
        await tunnel.forward_data(conn_id, tunnel_data)
    
    async def handle_conn_closed(self, session: 'Session', data: bytes):
        """연결 종료 처리"""
        offset = 0
        tunnel_name, offset = Protocol.unpack_string(data, offset)
        conn_id, offset = Protocol.unpack_uint32(data, offset)
        
        if tunnel_name in session.tunnels:
            tunnel = session.tunnels[tunnel_name]
            await tunnel.close_connection(conn_id)
    
    def generate_session_id(self) -> str:
        """세션 ID 생성"""
        import secrets
        return secrets.token_hex(8)
    
    def generate_conn_id(self) -> int:
        """연결 ID 생성"""
        self.conn_counter += 1
        return self.conn_counter


class Session:
    """클라이언트 세션"""
    
    def __init__(self, session_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.reader = reader
        self.writer = writer
        self.tunnels: Dict[str, 'Tunnel'] = {}


class Tunnel:
    """터널 클래스"""
    
    def __init__(self, name: str, tunnel_type: str, remote_port: int, local_addr: str, session: Session, server: Server):
        self.name = name
        self.type = tunnel_type
        self.remote_port = remote_port
        self.local_addr = local_addr
        self.session = session
        self.server = server
        self.listener = None
        self.udp_transport = None
        self.udp_protocol = None
        self.conns: Dict[int, asyncio.StreamWriter] = {}
        self.udp_addrs: Dict[int, Tuple[str, int]] = {}
    
    async def start(self):
        """터널 시작"""
        if self.type == 'tcp':
            await self.start_tcp()
        elif self.type == 'udp':
            await self.start_udp()
        else:
            raise ValueError(f"지원하지 않는 터널 타입: {self.type}")
    
    async def start_tcp(self):
        """TCP 터널 시작"""
        self.listener = await asyncio.start_server(
            self.handle_tcp_connection,
            '0.0.0.0',
            self.remote_port
        )
        
        logger.info(f"TCP 터널 리스닝: {self.name} -> {self.remote_port}")
    
    async def handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """TCP 연결 처리"""
        conn_id = self.server.generate_conn_id()
        remote_addr = writer.get_extra_info('peername')
        logger.info(f"새 연결: 터널={self.name}, ID={conn_id}, 원격={remote_addr}")
        
        self.conns[conn_id] = writer
        
        # 클라이언트에게 새 연결 요청
        await self.request_new_connection(conn_id)
        
        # 외부 연결에서 데이터 읽기
        try:
            while True:
                data = await reader.read(32 * 1024)
                if not data:
                    break
                
                # 클라이언트로 데이터 전달
                await self.send_data_to_client(conn_id, data)
        except Exception as e:
            logger.error(f"연결 읽기 오류: {e}")
        finally:
            await self.close_connection(conn_id)
    
    async def start_udp(self):
        """UDP 터널 시작"""
        loop = asyncio.get_event_loop()
        self.udp_protocol = UDPProtocol(self)
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: self.udp_protocol,
            local_addr=('0.0.0.0', self.remote_port)
        )
        
        logger.info(f"UDP 터널 리스닝: {self.name} -> {self.remote_port}")
    
    async def request_new_connection(self, conn_id: int):
        """클라이언트에게 새 연결 요청"""
        data = Protocol.pack_string(self.name)
        data += Protocol.pack_uint32(conn_id)
        
        await Protocol.write_message(self.session.writer, MSG_TYPE_NEW_CONN, data)
    
    async def send_data_to_client(self, conn_id: int, data: bytes):
        """클라이언트로 데이터 전송"""
        msg_data = Protocol.pack_string(self.name)
        msg_data += Protocol.pack_uint32(conn_id)
        msg_data += Protocol.pack_uint32(len(data)) + data
        
        await Protocol.write_message(self.session.writer, MSG_TYPE_DATA, msg_data)
    
    async def forward_data(self, conn_id: int, data: bytes):
        """데이터 전달"""
        if self.type == 'tcp':
            if conn_id in self.conns:
                writer = self.conns[conn_id]
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception as e:
                    logger.error(f"데이터 전달 오류: {e}")
                    await self.close_connection(conn_id)
        elif self.type == 'udp':
            if conn_id in self.udp_addrs:
                addr = self.udp_addrs[conn_id]
                self.udp_transport.sendto(data, addr)
    
    async def close_connection(self, conn_id: int):
        """연결 종료"""
        if self.type == 'tcp':
            if conn_id in self.conns:
                writer = self.conns[conn_id]
                writer.close()
                await writer.wait_closed()
                del self.conns[conn_id]
        elif self.type == 'udp':
            if conn_id in self.udp_addrs:
                del self.udp_addrs[conn_id]
    
    async def close(self):
        """터널 종료"""
        if self.listener:
            self.listener.close()
            await self.listener.wait_closed()
        
        if self.udp_transport:
            self.udp_transport.close()
        
        for conn_id in list(self.conns.keys()):
            await self.close_connection(conn_id)


class UDPProtocol(asyncio.DatagramProtocol):
    """UDP 프로토콜 핸들러"""
    
    def __init__(self, tunnel: Tunnel):
        self.tunnel = tunnel
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """UDP 패킷 수신"""
        # 기존 연결 ID 찾기 또는 새로 생성
        conn_id = None
        for cid, a in self.tunnel.udp_addrs.items():
            if a == addr:
                conn_id = cid
                break
        
        if conn_id is None:
            conn_id = self.tunnel.server.generate_conn_id()
            self.tunnel.udp_addrs[conn_id] = addr
        
        logger.info(f"UDP 패킷: 터널={self.tunnel.name}, ID={conn_id}, 원격={addr}")
        
        # 클라이언트에게 UDP 패킷 전달 요청
        asyncio.create_task(self.tunnel.send_udp_to_client(conn_id, data))
    
    def error_received(self, exc):
        """UDP 오류 수신"""
        logger.error(f"UDP 오류: {exc}")


# Tunnel에 UDP 전송 메서드 추가
async def send_udp_to_client(self, conn_id: int, data: bytes):
    """UDP 패킷을 클라이언트로 전송"""
    msg_data = Protocol.pack_string(self.name)
    msg_data += Protocol.pack_uint32(conn_id)
    msg_data += data
    
    await Protocol.write_message(self.session.writer, MSG_TYPE_NEW_CONN, msg_data)

Tunnel.send_udp_to_client = send_udp_to_client


class Client:
    """클라이언트 클래스"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.reader = None
        self.writer = None
        self.tunnels: Dict[str, 'ClientTunnel'] = {}
        self.reconnect = True
    
    async def start(self):
        """클라이언트 시작"""
        while True:
            try:
                await self.connect()
                
                # 모든 터널 생성
                for tunnel_config in self.config.tunnels:
                    await self.create_tunnel(tunnel_config)
                
                # 메시지 루프
                await self.message_loop()
            except Exception as e:
                logger.error(f"클라이언트 오류: {e}")
                if not self.reconnect:
                    break
                logger.info("재연결 시도 중...")
                await asyncio.sleep(5)
    
    async def connect(self):
        """서버에 연결"""
        host, port = self.config.server_addr.rsplit(':', 1)
        port = int(port)
        
        self.reader, self.writer = await asyncio.open_connection(host, port)
        logger.info(f"서버에 연결됨: {self.config.server_addr}")
        
        # 인증
        if self.config.token:
            token_data = Protocol.pack_string(self.config.token)
            self.writer.write(token_data)
            await self.writer.drain()
    
    async def create_tunnel(self, config: TunnelConfig):
        """터널 생성"""
        data = Protocol.pack_string(config.name)
        data += Protocol.pack_string(config.type)
        data += struct.pack('>H', config.remote_port)
        data += Protocol.pack_string(config.local_addr)
        
        await Protocol.write_message(self.writer, MSG_TYPE_NEW_TUNNEL, data)
        
        # 응답 대기
        msg_type, response_data = await Protocol.read_message(self.reader)
        
        if msg_type == MSG_TYPE_ERROR:
            error_msg, _ = Protocol.unpack_string(response_data)
            raise Exception(f"서버 오류: {error_msg}")
        
        if msg_type != MSG_TYPE_SUCCESS:
            raise Exception(f"예상치 못한 응답 타입: {msg_type}")
        
        tunnel = ClientTunnel(config, self)
        self.tunnels[config.name] = tunnel
        
        logger.info(f"터널 생성됨: {config.name} ({config.type}:{config.remote_port} -> {config.local_addr})")
    
    async def message_loop(self):
        """메시지 루프"""
        while True:
            try:
                msg_type, data = await Protocol.read_message(self.reader)
                
                if msg_type == MSG_TYPE_NEW_CONN:
                    await self.handle_new_connection(data)
                elif msg_type == MSG_TYPE_DATA:
                    await self.handle_tunnel_data(data)
                elif msg_type == MSG_TYPE_CONN_CLOSED:
                    await self.handle_conn_closed(data)
                else:
                    logger.warning(f"알 수 없는 메시지 타입: {msg_type}")
            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                logger.error(f"메시지 처리 오류: {e}")
                break
    
    async def handle_new_connection(self, data: bytes):
        """새 연결 요청 처리"""
        offset = 0
        tunnel_name, offset = Protocol.unpack_string(data, offset)
        conn_id, offset = Protocol.unpack_uint32(data, offset)
        
        if tunnel_name not in self.tunnels:
            logger.warning(f"터널을 찾을 수 없음: {tunnel_name}")
            return
        
        tunnel = self.tunnels[tunnel_name]
        
        if tunnel.config.type == 'tcp':
            await self.handle_new_tcp_connection(tunnel, conn_id)
        elif tunnel.config.type == 'udp':
            udp_data = data[offset:]
            if udp_data:
                await self.handle_udp_packet(tunnel, conn_id, udp_data)
    
    async def handle_new_tcp_connection(self, tunnel: 'ClientTunnel', conn_id: int):
        """새 TCP 연결 처리"""
        try:
            local_host, local_port = tunnel.config.local_addr.rsplit(':', 1)
            local_port = int(local_port)
            
            local_reader, local_writer = await asyncio.open_connection(local_host, local_port)
            logger.info(f"로컬 TCP 연결 성공: 터널={tunnel.config.name}, connID={conn_id}, 로컬={tunnel.config.local_addr}")
            
            tunnel.conns[conn_id] = local_writer
            
            # 양방향 프록시
            asyncio.create_task(self.proxy_tcp(tunnel, conn_id, local_reader, local_writer))
        except Exception as e:
            logger.error(f"로컬 TCP 연결 실패: {e}")
            await self.notify_conn_closed(tunnel, conn_id)
    
    async def proxy_tcp(self, tunnel: 'ClientTunnel', conn_id: int, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter):
        """TCP 프록시"""
        try:
            # 로컬 -> 서버
            async def local_to_server():
                try:
                    while True:
                        data = await local_reader.read(32 * 1024)
                        if not data:
                            break
                        
                        msg_data = Protocol.pack_string(tunnel.config.name)
                        msg_data += Protocol.pack_uint32(conn_id)
                        msg_data += data
                        
                        await Protocol.write_message(self.writer, MSG_TYPE_DATA, msg_data)
                except Exception as e:
                    logger.error(f"로컬 읽기 오류: {e}")
            
            task = asyncio.create_task(local_to_server())
            await task
        finally:
            local_writer.close()
            await local_writer.wait_closed()
            if conn_id in tunnel.conns:
                del tunnel.conns[conn_id]
            await self.notify_conn_closed(tunnel, conn_id)
    
    async def handle_udp_packet(self, tunnel: 'ClientTunnel', conn_id: int, data: bytes):
        """UDP 패킷 처리"""
        try:
            local_host, local_port = tunnel.config.local_addr.rsplit(':', 1)
            local_port = int(local_port)
            
            loop = asyncio.get_event_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: ClientUDPProtocol(tunnel, conn_id, self),
                remote_addr=(local_host, local_port)
            )
            
            transport.sendto(data)
            
            # 응답은 ClientUDPProtocol에서 처리
        except Exception as e:
            logger.error(f"UDP 패킷 처리 오류: {e}")
    
    async def handle_tunnel_data(self, data: bytes):
        """터널 데이터 처리"""
        offset = 0
        tunnel_name, offset = Protocol.unpack_string(data, offset)
        conn_id, offset = Protocol.unpack_uint32(data, offset)
        
        # 데이터 길이 읽기
        data_length, offset = Protocol.unpack_uint32(data, offset)
        tunnel_data = data[offset:offset+data_length]
        
        if tunnel_name not in self.tunnels:
            logger.warning(f"터널을 찾을 수 없음: {tunnel_name}")
            return
        
        tunnel = self.tunnels[tunnel_name]
        
        if tunnel.config.type == 'tcp':
            if conn_id in tunnel.conns:
                local_writer = tunnel.conns[conn_id]
                try:
                    local_writer.write(tunnel_data)
                    await local_writer.drain()
                except Exception as e:
                    logger.error(f"로컬 TCP 쓰기 오류: {e}")
                    await self.handle_conn_closed(data[:offset-4])
        elif tunnel.config.type == 'udp':
            await self.handle_udp_packet(tunnel, conn_id, tunnel_data)
    
    async def handle_conn_closed(self, data: bytes):
        """연결 종료 처리"""
        offset = 0
        tunnel_name, offset = Protocol.unpack_string(data, offset)
        conn_id, offset = Protocol.unpack_uint32(data, offset)
        
        if tunnel_name in self.tunnels:
            tunnel = self.tunnels[tunnel_name]
            if conn_id in tunnel.conns:
                local_writer = tunnel.conns[conn_id]
                local_writer.close()
                await local_writer.wait_closed()
                del tunnel.conns[conn_id]
    
    async def notify_conn_closed(self, tunnel: 'ClientTunnel', conn_id: int):
        """연결 종료 알림"""
        data = Protocol.pack_string(tunnel.config.name)
        data += Protocol.pack_uint32(conn_id)
        
        await Protocol.write_message(self.writer, MSG_TYPE_CONN_CLOSED, data)


class ClientTunnel:
    """클라이언트 터널"""
    
    def __init__(self, config: TunnelConfig, client: Client):
        self.config = config
        self.client = client
        self.conns: Dict[int, asyncio.StreamWriter] = {}


class ClientUDPProtocol(asyncio.DatagramProtocol):
    """클라이언트 UDP 프로토콜"""
    
    def __init__(self, tunnel: ClientTunnel, conn_id: int, client: Client):
        self.tunnel = tunnel
        self.conn_id = conn_id
        self.client = client
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """UDP 응답 수신"""
        msg_data = Protocol.pack_string(self.tunnel.config.name)
        msg_data += Protocol.pack_uint32(self.conn_id)
        msg_data += data
        
        asyncio.create_task(Protocol.write_message(self.client.writer, MSG_TYPE_DATA, msg_data))
        if self.transport:
            self.transport.close()
    
    def error_received(self, exc):
        logger.error(f"UDP 오류: {exc}")
        if self.transport:
            self.transport.close()


async def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='Reverse Proxy')
    parser.add_argument('-c', '--config', default='config.yaml', help='설정 파일 경로')
    args = parser.parse_args()
    
    try:
        config = Config(args.config)
    except Exception as e:
        logger.error(f"설정 로드 실패: {e}")
        sys.exit(1)
    
    try:
        if config.mode == 'server':
            logger.info("서버 모드로 시작합니다...")
            server = Server(config.server)
            await server.start()
        else:
            logger.info("클라이언트 모드로 시작합니다...")
            client = Client(config.client)
            await client.start()
    except KeyboardInterrupt:
        logger.info("종료 중...")
    except Exception as e:
        import traceback
        logger.error(f"실행 오류: {e}")
        logger.error(f"상세 오류:\n{traceback.format_exc()}")
        sys.exit(1)


if __name__ == '__main__':
    # Python 3.7+ 호환성: asyncio.run()이 없으면 loop.run_until_complete() 사용
    if hasattr(asyncio, 'run'):
        # Python 3.7+
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            logger.info("종료 중...")
    else:
        # Python 3.6 이하 호환
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            logger.info("종료 중...")
        finally:
            loop.close()
