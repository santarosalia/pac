# MapleStory Packet Analyzer

메이플스토리 패킷 분석기 - 고성능 패킷 감지, 복호화 및 내용 추출 도구

## 주요 기능

### 🔍 패킷 캡처 및 분석
- 실시간 네트워크 패킷 모니터링
- 프로세스별 포트 자동 감지
- 패킷 내용 분석 및 분류
- 의심스러운 패턴 검출

### 🔐 MapleStory 패킷 복호화
- **AES-OFB 복호화**: MapleStory의 주요 암호화 방식
- **Shanda 복호화**: Global/EU 서버용 추가 보안
- **버전별 키 관리**: v118 이전 정적 키 및 v120+ 이후 동적 키 지원
- **패킷 헤더 파싱**: 4바이트 헤더 및 2바이트 Opcode 분석

### 📊 데이터 파싱
- MapleStory 데이터 타입 지원 (Byte, Short, Int, Long, String)
- 비트 필드 분석 (버프 스탯 등)
- 16진수/ASCII 이중 출력
- 문자열 추출 (UTF-8, CP949, EUC-KR 지원)

## 설치 방법

```bash
# 의존성 설치
pip install -r requirements.txt

# 또는 개별 설치
pip install psutil scapy pycryptodome
```

## 사용 방법

```bash
python maplestory_packet_analyzer.py
```

### 설정 옵션

1. **MapleStory 버전 설정**: 복호화에 사용할 버전 선택
2. **암호화 키 설정**: 사용자 정의 IV 설정 (선택사항)
3. **프로세스 이름 입력**: 캡처할 MapleStory 프로세스 지정

## MapleStory 패킷 구조

### 패킷 형식
```
[4 bytes] 패킷 길이 (Little Endian)
[2 bytes] Opcode (작업 코드)
[N bytes] 페이로드 데이터
```

### 지원하는 암호화 방식
- **AES-OFB**: 256비트 키, 32바이트
- **Shanda**: XOR 기반 추가 보안
- **버전별 키**: v118 이전 정적, v120+ 이후 동적

### 데이터 타입
- **Byte**: 1바이트
- **Short**: 2바이트 (Little Endian)
- **Int**: 4바이트 (Little Endian)
- **Long**: 8바이트 (Little Endian)
- **String**: 2바이트 길이 + 문자열 데이터

## 로그 출력 예시

```
=== 패킷 분석 결과 ===
시간: 2024-01-01 12:00:00
소스: 192.168.1.100:12345
목적지: 192.168.1.200:8080
프로토콜: TCP
크기: 128 bytes
타입: maplestory_packet
패턴: movement, combat

=== 패킷 구조 ===
길이: 120 bytes
Opcode: 0x1234 (4660)
페이로드 크기: 120 bytes

복호화: 성공

=== 파싱된 데이터 ===
  byte: 1 (0x01)
  short: 12345 (0x3039)
  int: 987654321 (0x3ADE68B1)
  string: 'player_name' ('player_name')

=== 비트 필드 ===
  바이트 0: 0x68 (0b01101000) - 설정된 비트: [3, 5, 6]
```

## 주의사항

- 이 도구는 교육 및 연구 목적으로만 사용하세요
- 실제 게임 서버에 대한 무단 접근은 금지됩니다
- 개인정보 보호를 위해 민감한 데이터는 주의해서 다루세요

## 라이선스

이 프로젝트는 교육 목적으로 제작되었습니다.
