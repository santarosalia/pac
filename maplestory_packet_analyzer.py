#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메이플스토리 패킷 분석기
고성능 패킷 감지 및 내용 추출 도구
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

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('maplestory_packets.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

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
        """패킷 내용 분석 및 분류"""
        analysis = {
            'size': len(data),
            'strings': self.extract_strings(data),
            'patterns': [],
            'suspicious': False,
            'type': 'unknown'
        }
        
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
        """패킷 분석 및 로깅"""
        analysis = self.analyze_packet_content(packet_info['data'])
        
        # 통계 업데이트
        self.packet_stats[analysis['type']] += 1
        self.packet_stats['total'] += 1
        
        # 패킷 히스토리에 추가
        self.packet_history.append({
            'timestamp': packet_info['timestamp'],
            'type': analysis['type'],
            'size': packet_info['size'],
            'patterns': analysis['patterns']
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
        
        if analysis['strings']:
            log_msg += f"\n추출된 문자열:\n"
            for i, s in enumerate(analysis['strings'][:10]):  # 최대 10개만
                log_msg += f"  {i+1}. {s}\n"
                
        if analysis['suspicious'] or len(analysis['strings']) > 0:
            log_msg += f"\n원시 데이터:\n{self.format_hex_ascii(packet_info['data'])}\n"
            log_msg += f"\nUTF-8 디코딩:\n{packet_info['data'].decode('utf-8', errors='ignore')}\n"
            
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
    print("=== 메이플스토리 패킷 분석기 ===")
    print("고성능 패킷 감지 및 내용 추출 도구")
    print()
    
    analyzer = MaplePacketAnalyzer()
    
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
