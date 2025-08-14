#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메이플스토리 패킷 분석기
고성능 패킷 감지, 복호화 및 내용 추출 도구
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
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('maplestory_packets.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class MaplePacketDecryptor:
    """MapleStory 패킷 복호화 클래스"""
    
    def __init__(self):
        # 버전 118 이전의 정적 AES 키
        self.old_aes_key = bytes([
            0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
            0x06, 0x00, 0x00, 0x00, 0xB4, 0x00, 0x00, 0x00, 
            0x1B, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 
            0x33, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
        ])
        
        # 버전 120 이후의 패턴 키들
        self.version_keys = {
            145: "F981F775120E71D72BF6F89A9D225556467F019563AB79E180595D30AB298FDB",
            144: "467225B53CF2DC46A3A490B9B61CE7702FFD81C8AE65F2CB570B46B2B7C8185D",
            143: "FA3418B9E0A7F8AB436DA93DE837C3AEC9073D9B3F2EDC0C722DF03092E57327",
            142: "6DCCFD99233E30431347A41FE954ABBCEE9B4FD3276059CFA8F2AB4BCFEB0031",
            141: "5CFF9EAEC0941838C0FC378586DD411BEA73B1BC858C57AC0375C42C378F0203",
            125: "F981F775120E71D72BF6F89A9D225556467F019563AB79E180595D30AB298FDB",
            124: "467225B53CF2DC46A3A490B9B61CE7702FFD81C8AE65F2CB570B46B2B7C8185D",
            123: "FA3418B9E0A7F8AB436DA93DE837C3AEC9073D9B3F2EDC0C722DF03092E57327",
            122: "6DCCFD99233E30431347A41FE954ABBCEE9B4FD3276059CFA8F2AB4BCFEB0031",
            121: "5CFF9EAEC0941838C0FC378586DD411BEA73B1BC858C57AC0375C42C378F0203"
        }
        
        self.current_version = None
        self.current_aes_key = None
        self.send_iv = None
        self.recv_iv = None
        self.send_cipher = None
        self.recv_cipher = None
        
    def hex_to_bytes(self, hex_string):
        """16진수 문자열을 바이트로 변환"""
        return bytes.fromhex(hex_string)
    
    def set_version(self, version):
        """MapleStory 버전 설정 및 해당 키 로드"""
        self.current_version = version
        
        if version in self.version_keys:
            self.current_aes_key = self.hex_to_bytes(self.version_keys[version])
            logging.info(f"버전 {version} 키 로드됨")
        else:
            self.current_aes_key = self.old_aes_key
            logging.info(f"버전 {version} - 구버전 키 사용")
    
    def set_ivs(self, send_iv, recv_iv):
        """초기화 벡터 설정"""
        self.send_iv = send_iv
        self.recv_iv = recv_iv
        
        # AES-OFB 암호화 객체 생성
        if self.current_aes_key:
            self.send_cipher = AES.new(self.current_aes_key, AES.MODE_OFB, self.send_iv)
            self.recv_cipher = AES.new(self.current_aes_key, AES.MODE_OFB, self.recv_iv)
            logging.info("AES 암호화 객체 생성됨")
    
    def decrypt_packet_header(self, data):
        """패킷 헤더 복호화 (4바이트)"""
        if len(data) < 4:
            return None, data
            
        header = data[:4]
        payload = data[4:]
        
        # 헤더는 버전 정보와 패킷 길이를 포함
        # 실제 복호화는 MapleStory의 비트 시프트 알고리즘에 따라 달라짐
        try:
            # 간단한 XOR 복호화 시도 (실제로는 더 복잡함)
            decrypted_header = bytes([b ^ 0xAA for b in header])
            return decrypted_header, payload
        except:
            return header, payload
    
    def decrypt_aes_ofb(self, data, is_send=True):
        """AES-OFB 복호화"""
        if not self.current_aes_key or (is_send and not self.send_cipher) or (not is_send and not self.recv_cipher):
            return data
            
        try:
            cipher = self.send_cipher if is_send else self.recv_cipher
            decrypted = cipher.decrypt(data)
            return decrypted
        except Exception as e:
            logging.error(f"AES 복호화 오류: {e}")
            return data
    
    def decrypt_shanda(self, data):
        """Shanda 복호화 (간단한 구현)"""
        try:
            # Shanda는 주로 XOR 기반의 간단한 암호화
            # 실제 구현은 더 복잡할 수 있음
            key = 0x13
            decrypted = bytearray()
            
            for byte in data:
                decrypted.append(byte ^ key)
                key = (key + 1) % 256
                
            return bytes(decrypted)
        except Exception as e:
            logging.error(f"Shanda 복호화 오류: {e}")
            return data
    
    def decrypt_packet(self, data, is_encrypted=True, is_send=True):
        """패킷 전체 복호화"""
        if not is_encrypted:
            return data
            
        try:
            # 1단계: AES-OFB 복호화
            decrypted = self.decrypt_aes_ofb(data, is_send)
            
            # 2단계: Shanda 복호화 (Global/EU 서버용)
            decrypted = self.decrypt_shanda(decrypted)
            
            return decrypted
        except Exception as e:
            logging.error(f"패킷 복호화 오류: {e}")
            return data

class MaplePacketParser:
    """MapleStory 패킷 파서 클래스"""
    
    def __init__(self):
        self.decryptor = MaplePacketDecryptor()
        
    def parse_packet_structure(self, data):
        """패킷 구조 파싱"""
        if len(data) < 6:  # 최소 헤더 + opcode
            return None
            
        try:
            # 패킷 길이 (4바이트)
            packet_length = struct.unpack('<I', data[:4])[0]
            
            # Opcode (2바이트)
            opcode = struct.unpack('<H', data[4:6])[0]
            
            # 페이로드
            payload = data[6:6+packet_length] if len(data) >= 6+packet_length else data[6:]
            
            return {
                'length': packet_length,
                'opcode': opcode,
                'opcode_hex': f"0x{opcode:04X}",
                'payload': payload,
                'total_size': len(data)
            }
        except Exception as e:
            logging.error(f"패킷 구조 파싱 오류: {e}")
            return None
    
    def parse_data_types(self, data):
        """MapleStory 데이터 타입 파싱"""
        parsed_data = []
        offset = 0
        
        while offset < len(data):
            try:
                if offset + 1 <= len(data):
                    # Byte
                    byte_val = struct.unpack('<B', data[offset:offset+1])[0]
                    parsed_data.append(('byte', byte_val, f"0x{byte_val:02X}"))
                    offset += 1
                    continue
                    
                if offset + 2 <= len(data):
                    # Short
                    short_val = struct.unpack('<H', data[offset:offset+2])[0]
                    parsed_data.append(('short', short_val, f"0x{short_val:04X}"))
                    offset += 2
                    continue
                    
                if offset + 4 <= len(data):
                    # Int
                    int_val = struct.unpack('<I', data[offset:offset+4])[0]
                    parsed_data.append(('int', int_val, f"0x{int_val:08X}"))
                    offset += 4
                    continue
                    
                if offset + 8 <= len(data):
                    # Long
                    long_val = struct.unpack('<Q', data[offset:offset+8])[0]
                    parsed_data.append(('long', long_val, f"0x{long_val:016X}"))
                    offset += 8
                    continue
                    
                # String (길이 + 데이터)
                if offset + 2 <= len(data):
                    str_len = struct.unpack('<H', data[offset:offset+2])[0]
                    if offset + 2 + str_len <= len(data):
                        try:
                            string_val = data[offset+2:offset+2+str_len].decode('utf-8', errors='ignore')
                            parsed_data.append(('string', string_val, f"'{string_val}'"))
                            offset += 2 + str_len
                            continue
                        except:
                            pass
                            
                # 파싱할 수 없는 데이터는 건너뛰기
                offset += 1
                
            except Exception as e:
                offset += 1
                continue
                
        return parsed_data
    
    def parse_bit_fields(self, data):
        """비트 필드 파싱 (버프 스탯 등)"""
        bit_fields = []
        
        for i, byte in enumerate(data):
            if byte != 0:  # 0이 아닌 바이트만 분석
                bits = []
                for bit_pos in range(8):
                    mask = 1 << bit_pos
                    if byte & mask:
                        bits.append(bit_pos)
                        
                if bits:
                    bit_fields.append({
                        'byte_index': i,
                        'byte_value': f"0x{byte:02X}",
                        'binary': f"0b{byte:08b}",
                        'set_bits': bits
                    })
                    
        return bit_fields

class MaplePacketAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packet_stats = defaultdict(int)
        self.known_patterns = {
            'login': rb'login|auth|password',
            'chat': rb'chat|message|whisper',
            'movement': rb'move|position|coord',
            'combat': rb'attack|damage|skill',
            'inventory': rb'inventory|item|equip',
            'trade': rb'trade|shop|buy|sell',
            'guild': rb'guild|clan|alliance',
            'party': rb'party|group|member'
        }
        self.packet_history = deque(maxlen=1000)
        self.running = False
        self.analysis_thread = None
        
        # 패킷 파서 및 복호화기 초기화
        self.packet_parser = MaplePacketParser()
        self.decryptor = MaplePacketDecryptor()
        
        # MapleStory 버전 설정 (사용자가 변경 가능)
        self.decryptor.set_version(145)  # 기본값
        
    def set_maplestory_version(self, version):
        """MapleStory 버전 설정"""
        self.decryptor.set_version(version)
        logging.info(f"MapleStory 버전 {version}으로 설정됨")
        
    def set_encryption_keys(self, send_iv, recv_iv):
        """암호화 키 설정"""
        self.decryptor.set_ivs(send_iv, recv_iv)
        logging.info("암호화 키 설정됨")

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

    def analyze_packet_content(self, data):
        """패킷 내용 분석 및 분류 (복호화 포함)"""
        analysis = {
            'size': len(data),
            'strings': self.extract_strings(data),
            'patterns': [],
            'suspicious': False,
            'type': 'unknown',
            'decrypted': False,
            'parsed_data': None,
            'bit_fields': None
        }
        
        # 패킷 구조 파싱 시도
        packet_structure = self.packet_parser.parse_packet_structure(data)
        if packet_structure:
            analysis['packet_structure'] = packet_structure
            analysis['type'] = 'maplestory_packet'
            
            # 복호화 시도
            try:
                decrypted_payload = self.decryptor.decrypt_packet(
                    packet_structure['payload'], 
                    is_encrypted=True,
                    is_send=True
                )
                
                if decrypted_payload != packet_structure['payload']:
                    analysis['decrypted'] = True
                    analysis['decrypted_payload'] = decrypted_payload
                    
                    # 복호화된 데이터 파싱
                    parsed_data = self.packet_parser.parse_data_types(decrypted_payload)
                    analysis['parsed_data'] = parsed_data
                    
                    # 비트 필드 분석
                    bit_fields = self.packet_parser.parse_bit_fields(decrypted_payload)
                    analysis['bit_fields'] = bit_fields
                    
            except Exception as e:
                logging.error(f"복호화 오류: {e}")
        
        # 패턴 매칭
        for pattern_name, pattern in self.known_patterns.items():
            if re.search(pattern, data, re.IGNORECASE):
                analysis['patterns'].append(pattern_name)
                
        # 의심스러운 패턴 검출
        suspicious_patterns = [
            rb'\x00{4,}',  # 연속된 null bytes
            rb'\xFF{4,}',  # 연속된 0xFF
            rb'admin|hack|cheat|bot',  # 의심스러운 키워드
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                analysis['suspicious'] = True
                break
                
        # 패킷 타입 추정
        if len(data) < 10:
            analysis['type'] = 'control'
        elif len(analysis['strings']) > 5:
            analysis['type'] = 'data'
        elif len(data) > 1000:
            analysis['type'] = 'large_data'
            
        return analysis

    def packet_callback(self, packet):
        """패킷 캡처 콜백 (비동기 처리)"""
        try:
            if Raw in packet:
                raw_data = packet[Raw].load
                
                # 패킷 정보 수집
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[IP].src if IP in packet else 'unknown',
                    'dst_ip': packet[IP].dst if IP in packet else 'unknown',
                    'src_port': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                    'dst_port': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Unknown',
                    'data': raw_data,
                    'size': len(raw_data)
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
        """패킷 분석 및 로깅 (복호화 결과 포함)"""
        analysis = self.analyze_packet_content(packet_info['data'])
        
        # 통계 업데이트
        self.packet_stats[analysis['type']] += 1
        self.packet_stats['total'] += 1
        
        # 패킷 히스토리에 추가
        self.packet_history.append({
            'timestamp': packet_info['timestamp'],
            'type': analysis['type'],
            'size': packet_info['size'],
            'patterns': analysis['patterns'],
            'decrypted': analysis.get('decrypted', False)
        })
        
        # 로그 출력
        log_msg = f"""
=== 패킷 분석 결과 ===
시간: {packet_info['timestamp']}
소스: {packet_info['src_ip']}:{packet_info['src_port']}
목적지: {packet_info['dst_ip']}:{packet_info['dst_port']}
프로토콜: {packet_info['protocol']}
크기: {packet_info['size']} bytes
타입: {analysis['type']}
패턴: {', '.join(analysis['patterns']) if analysis['patterns'] else '없음'}
의심스러움: {'예' if analysis['suspicious'] else '아니오'}
"""
        
        # 패킷 구조 정보
        if 'packet_structure' in analysis:
            ps = analysis['packet_structure']
            log_msg += f"""
=== 패킷 구조 ===
길이: {ps['length']} bytes
Opcode: {ps['opcode_hex']} ({ps['opcode']})
페이로드 크기: {len(ps['payload'])} bytes
"""
        
        # 복호화 결과
        if analysis.get('decrypted', False):
            log_msg += f"복호화: 성공\n"
            
            # 파싱된 데이터
            if analysis.get('parsed_data'):
                log_msg += f"\n=== 파싱된 데이터 ===\n"
                for data_type, value, hex_repr in analysis['parsed_data'][:20]:  # 최대 20개
                    log_msg += f"  {data_type}: {value} ({hex_repr})\n"
            
            # 비트 필드
            if analysis.get('bit_fields'):
                log_msg += f"\n=== 비트 필드 ===\n"
                for bf in analysis['bit_fields'][:10]:  # 최대 10개
                    log_msg += f"  바이트 {bf['byte_index']}: {bf['byte_value']} ({bf['binary']}) - 설정된 비트: {bf['set_bits']}\n"
        else:
            log_msg += f"복호화: 실패 또는 불필요\n"
        
        if analysis['strings']:
            log_msg += f"\n추출된 문자열:\n"
            for i, s in enumerate(analysis['strings'][:10]):  # 최대 10개만
                log_msg += f"  {i+1}. {s}\n"
                
        if analysis['suspicious'] or len(analysis['strings']) > 0:
            log_msg += f"\n원시 데이터:\n{self.format_hex_ascii(packet_info['data'])}\n"
            
        logging.info(log_msg)

    def start_capture(self, target_process):
        """패킷 캡처 시작"""
        ports = self.get_ports_by_process_name(target_process)
        
        if not ports:
            logging.error(f"'{target_process}' 관련 포트를 찾을 수 없습니다.")
            return False
            
        logging.info(f"발견된 포트: {ports}")
        
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

def main():
    """메인 함수"""
    print("=== 메이플스토리 패킷 분석기 (복호화 기능 포함) ===")
    print("고성능 패킷 감지, 복호화 및 내용 추출 도구")
    print()
    
    analyzer = MaplePacketAnalyzer()
    
    # MapleStory 버전 설정
    try:
        version = input("MapleStory 버전을 입력하세요 (기본값: 145): ").strip()
        if version:
            analyzer.set_maplestory_version(int(version))
    except ValueError:
        print("잘못된 버전입니다. 기본값 145을 사용합니다.")
    
    # 암호화 키 설정 (선택사항)
    try:
        set_keys = input("암호화 키를 설정하시겠습니까? (y/N): ").strip().lower()
        if set_keys == 'y':
            send_iv_hex = input("송신 IV (16진수, 32자): ").strip()
            recv_iv_hex = input("수신 IV (16진수, 32자): ").strip()
            
            if len(send_iv_hex) == 32 and len(recv_iv_hex) == 32:
                send_iv = bytes.fromhex(send_iv_hex)
                recv_iv = bytes.fromhex(recv_iv_hex)
                analyzer.set_encryption_keys(send_iv, recv_iv)
                print("암호화 키가 설정되었습니다.")
            else:
                print("잘못된 IV 형식입니다. 기본값을 사용합니다.")
    except Exception as e:
        print(f"키 설정 오류: {e}")
    
    # 대상 프로세스 입력
    target_process = input("캡처할 프로세스 이름을 입력하세요 (예: MapleStory): ").strip()
    
    if not target_process:
        print("프로세스 이름을 입력해주세요.")
        return
        
    # 캡처 시작
    success = analyzer.start_capture(target_process)
    
    if not success:
        print("캡처를 시작할 수 없습니다.")
        return

if __name__ == "__main__":
    main()
