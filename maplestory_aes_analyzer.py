#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메이플스토리 패킷 분석기 (AES 복호화 포함)
고성능 패킷 감지 및 내용 추출 도구
MapleShark 기반 AES 복호화 구현
"""

import psutil
import threading
import time
import re
import struct
import json
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, Raw, IP, TCP, UDP
import queue
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

# 로깅 설정
logging.basicConfig(
    level=logging.DEBUG,  # 디버그 레벨로 변경
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('maplestory_aes_packets.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class MapleAES:
    """메이플스토리 AES 복호화 클래스 (MapleShark 기반)"""
    
    def __init__(self):
        # MapleShark의 실제 키 생성 방식
        self.version_keys = {
            'GMS': b'GMS',
            'KMS': b'KMS', 
            'JMS': b'JMS',
            'CMS': b'CMS',
            'TMS': b'TMS',
            'SEA': b'SEA',
            'EMS': b'EMS'
        }
        
        # 현재 사용 중인 키와 IV
        self.current_key = None
        self.current_iv = None
        
        # 메이플스토리 기본 키 (MapleShark에서 가져옴)
        self.base_key = b'MapleStory'
        
    def generate_key(self, version='GMS'):
        """MapleShark 방식으로 AES 키 생성"""
        if version in self.version_keys:
            version_key = self.version_keys[version]
        else:
            version_key = b'GMS'  # 기본값
            
        # MapleShark의 실제 키 생성 방식
        # 1. 기본 키와 버전 키를 결합
        key_material = self.base_key + version_key
        
        # 2. MD5 해시로 16바이트 키 생성
        key_hash = hashlib.md5(key_material).digest()
        
        # 3. 16바이트로 정확히 맞춤
        if len(key_hash) < 16:
            key_hash = key_hash + b'\x00' * (16 - len(key_hash))
        elif len(key_hash) > 16:
            key_hash = key_hash[:16]
            
        return key_hash
        
    def set_version(self, version='GMS'):
        """버전 설정 및 키 업데이트"""
        self.current_key = self.generate_key(version)
        # MapleShark는 IV를 0으로 설정
        self.current_iv = b'\x00' * 16
        logging.info(f"AES 키 설정 완료: {version} 버전")
        logging.info(f"키 (hex): {self.current_key.hex()}")
        
    def decrypt_packet(self, encrypted_data):
        """MapleShark 방식으로 AES 복호화 수행"""
        if not self.current_key:
            self.set_version()  # 기본 키 사용
            
        try:
            # 메이플스토리 패킷 구조 확인
            if len(encrypted_data) < 4:
                return None, "패킷이 너무 짧습니다"
                
            # MapleShark 방식: 패킷 길이 확인 (첫 2바이트)
            try:
                packet_length = struct.unpack('<H', encrypted_data[:2])[0]
                logging.debug(f"패킷 길이: {packet_length}, 실제 길이: {len(encrypted_data)}")
            except struct.error:
                return None, "패킷 길이 파싱 실패"
                
            # 실제 암호화된 데이터 (헤더 제외)
            data_to_decrypt = encrypted_data[2:]
            
            # 16바이트 블록으로 패딩 확인
            if len(data_to_decrypt) % 16 != 0:
                padding_needed = 16 - (len(data_to_decrypt) % 16)
                data_to_decrypt += b'\x00' * padding_needed
                logging.debug(f"패딩 추가: {padding_needed} 바이트")
                
            # MapleShark는 CBC 모드를 사용 (ECB가 아님)
            cipher = AES.new(self.current_key, AES.MODE_CBC, self.current_iv)
            decrypted_data = cipher.decrypt(data_to_decrypt)
            
            # PKCS7 패딩 제거 시도
            try:
                decrypted_data = unpad(decrypted_data, 16)
                logging.debug("PKCS7 패딩 제거 성공")
            except ValueError:
                # 패딩이 없는 경우 그대로 사용
                logging.debug("PKCS7 패딩 없음, 원본 데이터 사용")
                pass
                
            return decrypted_data, None
            
        except Exception as e:
            return None, f"복호화 오류: {str(e)}"
            
    def is_maplestory_packet(self, data):
        """메이플스토리 패킷인지 확인 (MapleShark 방식)"""
        if len(data) < 4:
            return False
            
        try:
            # 패킷 길이 확인 (첫 2바이트)
            packet_length = struct.unpack('<H', data[:2])[0]
            
            # 메이플스토리 패킷 길이 범위 확인
            if 4 <= packet_length <= 65535:
                # 길이가 일치하는지 확인
                if packet_length == len(data):
                    return True
                # 또는 길이가 실제 데이터보다 작은 경우 (일부 패킷)
                elif packet_length <= len(data):
                    return True
                    
        except struct.error:
            pass
            
        # 메이플스토리 시그니처 확인
        if data.startswith(b'Maple') or b'Maple' in data:
            return True
            
        # 특정 포트나 패턴으로 메이플스토리 패킷 추정
        if len(data) > 10 and data[0] == 0x00 and data[1] == 0x00:
            return True
            
        return False

class MaplePacketAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packet_stats = defaultdict(int)
        self.known_patterns = {
            'login': rb'login|auth|password|account',
            'chat': rb'chat|message|whisper|say',
            'movement': rb'move|position|coord|pos',
            'combat': rb'attack|damage|skill|mob',
            'inventory': rb'inventory|item|equip|slot',
            'trade': rb'trade|shop|buy|sell|merchant',
            'guild': rb'guild|clan|alliance',
            'party': rb'party|group|member|invite',
            'map': rb'map|field|portal|warp',
            'quest': rb'quest|mission|objective'
        }
        self.packet_history = deque(maxlen=1000)
        self.running = False
        self.analysis_thread = None
        
        # AES 복호화기 초기화
        self.aes_decryptor = MapleAES()
        self.aes_decryptor.set_version('GMS')  # 기본 GMS 버전
        
    def get_ports_by_process_name(self, proc_name):
        """프로세스 이름으로 TCP/UDP 포트 찾기 (개선된 버전)"""
        ports = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['name'] and proc_name.lower() in proc.info['name'].lower():
                        # 프로세스의 모든 네트워크 연결 확인
                        for conn in proc.connections(kind='inet'):
                            if conn.laddr and conn.laddr.port:
                                ports.add(conn.laddr.port)
                            if conn.raddr and conn.raddr.port:
                                ports.add(conn.raddr.port)
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logging.error(f"포트 검색 중 오류: {e}")
        return list(ports)

    def extract_strings(self, data, min_len=3):
        """바이너리 데이터에서 연속된 ASCII 문자열 추출 (개선된 버전)"""
        strings = []
        # 다양한 인코딩으로 문자열 추출 시도
        encodings = ['utf-8', 'cp949', 'euc-kr', 'ascii']
        
        # 정규식으로 문자열 찾기
        pattern = rb'[ -~]{%d,}' % min_len
        matches = re.findall(pattern, data)
        
        for match in matches:
            for encoding in encodings:
                try:
                    decoded = match.decode(encoding)
                    if len(decoded.strip()) >= min_len:
                        strings.append(decoded.strip())
                    break
                except UnicodeDecodeError:
                    continue
                    
        return list(set(strings))  # 중복 제거

    def format_hex_ascii(self, data, width=16):
        """16진수와 ASCII를 같이 출력 (개선된 버전)"""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_chunk = ' '.join(f"{b:02X}" for b in chunk)
            ascii_chunk = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
            offset = f"{i:04X}"
            lines.append(f"{offset}: {hex_chunk:<48} {ascii_chunk}")
        return '\n'.join(lines)

    def analyze_packet_content(self, data, decrypted_data=None):
        """패킷 내용 분석 및 분류 (MapleShark AES 복호화 포함)"""
        analysis = {
            'size': len(data),
            'strings': [],
            'patterns': [],
            'suspicious': False,
            'type': 'unknown',
            'encrypted': False,
            'decrypted': False,
            'decrypted_strings': [],
            'packet_info': {}
        }
        
        # 메이플스토리 패킷 정보 추출
        if len(data) >= 4:
            try:
                packet_length = struct.unpack('<H', data[:2])[0]
                analysis['packet_info']['length'] = packet_length
                analysis['packet_info']['header'] = data[:4].hex()
            except struct.error:
                analysis['packet_info']['length'] = 'unknown'
                analysis['packet_info']['header'] = 'invalid'
        
        # 원본 데이터에서 문자열 추출
        analysis['strings'] = self.extract_strings(data)
        
        # 복호화된 데이터가 있으면 분석
        if decrypted_data:
            analysis['decrypted'] = True
            analysis['decrypted_strings'] = self.extract_strings(decrypted_data)
            
            # 복호화된 데이터로 패턴 매칭
            for pattern_name, pattern in self.known_patterns.items():
                if re.search(pattern, decrypted_data, re.IGNORECASE):
                    analysis['patterns'].append(f"{pattern_name}(복호화)")
        else:
            # 원본 데이터로 패턴 매칭
            for pattern_name, pattern in self.known_patterns.items():
                if re.search(pattern, data, re.IGNORECASE):
                    analysis['patterns'].append(pattern_name)
                    
        # 의심스러운 패턴 검출
        suspicious_patterns = [
            rb'\x00{4,}',  # 연속된 null bytes
            rb'\xFF{4,}',  # 연속된 0xFF
            rb'admin|hack|cheat|bot|exploit',  # 의심스러운 키워드
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                analysis['suspicious'] = True
                break
                
        # 패킷 타입 추정
        if len(data) < 10:
            analysis['type'] = 'control'
        elif len(analysis['strings']) > 5 or (decrypted_data and len(analysis['decrypted_strings']) > 5):
            analysis['type'] = 'data'
        elif len(data) > 1000:
            analysis['type'] = 'large_data'
            
        return analysis

    def packet_callback(self, packet):
        """패킷 캡처 콜백 (MapleShark AES 복호화 포함)"""
        try:
            if Raw in packet:
                raw_data = packet[Raw].load
                
                # 메이플스토리 패킷인지 확인 (MapleShark 방식)
                is_maplestory = self.aes_decryptor.is_maplestory_packet(raw_data)
                
                # AES 복호화 시도
                decrypted_data = None
                decrypt_error = None
                
                if is_maplestory:
                    logging.debug(f"메이플스토리 패킷 감지: {len(raw_data)} bytes")
                    decrypted_data, decrypt_error = self.aes_decryptor.decrypt_packet(raw_data)
                    
                    if decrypted_data:
                        logging.debug(f"복호화 성공: {len(decrypted_data)} bytes")
                    else:
                        logging.debug(f"복호화 실패: {decrypt_error}")
                
                # 패킷 정보 수집
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[IP].src if IP in packet else 'unknown',
                    'dst_ip': packet[IP].dst if IP in packet else 'unknown',
                    'src_port': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                    'dst_port': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Unknown',
                    'data': raw_data,
                    'size': len(raw_data),
                    'is_maplestory': is_maplestory,
                    'decrypted_data': decrypted_data,
                    'decrypt_error': decrypt_error
                }
                
                # 큐에 추가 (비동기 처리)
                try:
                    self.packet_queue.put_nowait(packet_info)
                except queue.Full:
                    logging.warning("패킷 큐가 가득 찼습니다. 오래된 패킷을 제거합니다.")
                    try:
                        self.packet_queue.get_nowait()  # 오래된 패킷 제거
                        self.packet_queue.put_nowait(packet_info)
                    except queue.Empty:
                        pass
                        
        except Exception as e:
            logging.error(f"패킷 처리 중 오류: {e}")

    def process_packets(self):
        """패킷 처리 스레드"""
        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1)
                self.analyze_and_log_packet(packet_info)
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"패킷 처리 스레드 오류: {e}")

    def analyze_and_log_packet(self, packet_info):
        """패킷 분석 및 로깅 (AES 복호화 포함)"""
        analysis = self.analyze_packet_content(
            packet_info['data'], 
            packet_info['decrypted_data']
        )
        
        # 통계 업데이트
        self.packet_stats[analysis['type']] += 1
        self.packet_stats['total'] += 1
        
        if packet_info['is_maplestory']:
            self.packet_stats['maplestory'] += 1
        if analysis['decrypted']:
            self.packet_stats['decrypted'] += 1
        
        # 패킷 히스토리에 추가
        self.packet_history.append({
            'timestamp': packet_info['timestamp'],
            'type': analysis['type'],
            'size': packet_info['size'],
            'patterns': analysis['patterns'],
            'is_maplestory': packet_info['is_maplestory'],
            'decrypted': analysis['decrypted']
        })
        
        # 로그 출력
        log_msg = f"""
=== 패킷 분석 결과 (MapleShark 방식) ===
시간: {packet_info['timestamp']}
소스: {packet_info['src_ip']}:{packet_info['src_port']}
목적지: {packet_info['dst_ip']}:{packet_info['dst_port']}
프로토콜: {packet_info['protocol']}
크기: {packet_info['size']} bytes
타입: {analysis['type']}
메이플스토리 패킷: {'예' if packet_info['is_maplestory'] else '아니오'}
AES 복호화: {'성공' if analysis['decrypted'] else '실패'}
패턴: {', '.join(analysis['patterns']) if analysis['patterns'] else '없음'}
의심스러움: {'예' if analysis['suspicious'] else '아니오'}
"""
        
        # MapleShark 패킷 정보 추가
        if analysis['packet_info']:
            log_msg += f"패킷 헤더: {analysis['packet_info'].get('header', 'N/A')}\n"
            log_msg += f"패킷 길이: {analysis['packet_info'].get('length', 'N/A')}\n"
        
        # 복호화 오류가 있으면 표시
        if packet_info['decrypt_error']:
            log_msg += f"복호화 오류: {packet_info['decrypt_error']}\n"
        
        # 원본 문자열
        if analysis['strings']:
            log_msg += f"\n원본 문자열:\n"
            for i, s in enumerate(analysis['strings'][:5]):  # 최대 5개만
                log_msg += f"  {i+1}. {s}\n"
                
        # 복호화된 문자열
        if analysis['decrypted_strings']:
            log_msg += f"\n복호화된 문자열:\n"
            for i, s in enumerate(analysis['decrypted_strings'][:10]):  # 최대 10개만
                log_msg += f"  {i+1}. {s}\n"
                
        # 의심스럽거나 문자열이 있는 경우 원시 데이터 출력
        if analysis['suspicious'] or len(analysis['strings']) > 0 or len(analysis['decrypted_strings']) > 0:
            log_msg += f"\n원시 데이터:\n{self.format_hex_ascii(packet_info['data'])}\n"
            
            # 복호화된 데이터도 출력
            if packet_info['decrypted_data']:
                log_msg += f"\n복호화된 데이터:\n{self.format_hex_ascii(packet_info['decrypted_data'])}\n"
            
        logging.info(log_msg)

    def start_capture(self, target_process, version='GMS'):
        """패킷 캡처 시작"""
        # AES 버전 설정
        self.aes_decryptor.set_version(version)
        
        ports = self.get_ports_by_process_name(target_process)
        
        if not ports:
            logging.error(f"'{target_process}' 관련 포트를 찾을 수 없습니다.")
            return False
            
        logging.info(f"발견된 포트: {ports}")
        logging.info(f"AES 버전: {version}")
        
        # 필터 문자열 생성
        filter_str = " or ".join([f"tcp port {p}" for p in ports])
        logging.info(f"필터: {filter_str}")
        
        # 분석 스레드 시작
        self.running = True
        self.analysis_thread = threading.Thread(target=self.process_packets)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        # 통계 출력 스레드
        stats_thread = threading.Thread(target=self.print_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        logging.info("패킷 캡처를 시작합니다. (Ctrl+C로 종료)")
        
        try:
            sniff(filter=filter_str, prn=self.packet_callback, store=False)
        except KeyboardInterrupt:
            logging.info("캡처를 중단합니다.")
        finally:
            self.stop_capture()
            
        return True

    def print_stats(self):
        """주기적으로 통계 출력"""
        while self.running:
            time.sleep(30)  # 30초마다
            if self.packet_stats:
                logging.info(f"통계: {dict(self.packet_stats)}")

    def stop_capture(self):
        """캡처 중지"""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
            
        # 최종 통계 출력
        logging.info("=== 최종 통계 ===")
        for key, value in self.packet_stats.items():
            logging.info(f"{key}: {value}")

def test_maple_aes():
    """MapleShark AES 복호화 테스트 함수"""
    print("=== MapleShark AES 복호화 테스트 ===")
    
    aes = MapleAES()
    
    # 다양한 버전으로 키 생성 테스트
    versions = ['GMS', 'KMS', 'JMS']
    for version in versions:
        aes.set_version(version)
        print(f"{version} 버전 키: {aes.current_key.hex()}")
    
    # 테스트 데이터로 복호화 테스트
    print("\n=== 복호화 테스트 ===")
    
    # 가상의 메이플스토리 패킷 (길이 + 데이터)
    test_data = b'\x00\x10' + b'TestPacketData' + b'\x00' * 2  # 16바이트로 맞춤
    
    print(f"테스트 데이터: {test_data.hex()}")
    print(f"데이터 길이: {len(test_data)} bytes")
    
    # 패킷 감지 테스트
    is_maplestory = aes.is_maplestory_packet(test_data)
    print(f"메이플스토리 패킷: {'예' if is_maplestory else '아니오'}")
    
    # 복호화 테스트 (실제로는 암호화된 데이터여야 함)
    if is_maplestory:
        decrypted, error = aes.decrypt_packet(test_data)
        if decrypted:
            print(f"복호화 성공: {len(decrypted)} bytes")
            print(f"복호화된 데이터: {decrypted.hex()}")
        else:
            print(f"복호화 실패: {error}")
    
    print("\n테스트 완료!")

def main():
    """메인 함수"""
    print("=== 메이플스토리 패킷 분석기 (MapleShark AES 복호화) ===")
    print("고성능 패킷 감지 및 내용 추출 도구")
    print("MapleShark 기반 AES 복호화 구현")
    print()
    
    # 테스트 모드 확인
    test_mode = input("테스트 모드를 실행하시겠습니까? (y/n, 기본값: n): ").strip().lower()
    if test_mode in ['y', 'yes', '예']:
        test_maple_aes()
        print()
    
    analyzer = MaplePacketAnalyzer()
    
    # 대상 프로세스 입력
    target_process = input("캡처할 프로세스 이름을 입력하세요 (예: MapleStory): ").strip()
    
    if not target_process:
        print("프로세스 이름을 입력해주세요.")
        return
        
    # AES 버전 선택
    print("\n사용 가능한 AES 버전:")
    versions = ['GMS', 'KMS', 'JMS', 'CMS', 'TMS', 'SEA', 'EMS']
    for i, version in enumerate(versions, 1):
        print(f"  {i}. {version}")
    
    try:
        version_choice = int(input(f"\nAES 버전을 선택하세요 (1-{len(versions)}, 기본값: 1): ").strip() or "1")
        if 1 <= version_choice <= len(versions):
            selected_version = versions[version_choice - 1]
        else:
            selected_version = 'GMS'
    except ValueError:
        selected_version = 'GMS'
        
    print(f"선택된 AES 버전: {selected_version}")
    
    # 캡처 시작
    success = analyzer.start_capture(target_process, selected_version)
    
    if not success:
        print("캡처를 시작할 수 없습니다.")
        return

if __name__ == "__main__":
    main()
