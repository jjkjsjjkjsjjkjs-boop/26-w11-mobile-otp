# 모바일 OTP — TOTP 2단계 인증 (`26-w11-mobile-otp`)

> 이 프로젝트는 Google Authenticator, Microsoft Authenticator처럼 **인터넷 연결 없이도 30초마다 동일한 6자리 인증 번호를 생성하는 모바일 OTP(TOTP, RFC 6238)** 웹앱이자 2단계 인증(2FA) 시뮬레이터입니다.

---

## 🌟 프로젝트 소개

**CyberOTP Studio**는 웹 서비스 관점의 **2단계 로그인 인증 서버(Service Provider)**와 스마트폰 관점의 **모바일 인증기(Authenticator Client)**를 한 화면에서 실시간으로 비교·체험할 수 있는 반응형 듀얼 뷰 스튜디오입니다.

- **2FA 인증 서버**: 안전한 Base32 비밀 키 발급, 스마트폰 등록용 `otpauth://` QR 코드 렌더링, 6자리 번호 판정 및 시간 오차(±30초) 허용 검증.
- **모바일 웹 인증기**: 스마트폰 Authenticator UI를 재현하여 30초 원형 SVG 타이머 및 다중 계정(GitHub, AWS 등)의 6자리 OTP를 실시간 갱신.
- **사이버보안 분석실**: 비밀키 생성부터 최종 6자리 도출까지 RFC 6238의 5단계 암호학적 연산 과정을 실시간 투명하게 시각화.

---

## 🧭 나의 AI 기획·구현 과정

1. **선택한 AI 협업 방식**:
   - **Antigravity IDE 대화형 기획(Implementation Plan) & 단계별 검증 방식**을 선택했습니다.
   - 보안 필수 원칙(RFC 6238 준수, CSPRNG 난수 생성, Zero-Transmission)을 명확히 수립한 후, `src/utils/totp.js` 핵심 암호화 모듈을 먼저 개발하고 RFC 표준 테스트 벡터로 수학적 무결성을 검증한 뒤 UI를 빌드했습니다.

2. **화면 및 기능 구상**:
   - 단순히 번호만 출력하는 것에 그치지 않고, 사용자가 2FA의 전체 라이프사이클을 이해할 수 있도록 **[서비스 등록 & QR 스캔 & 2FA 검증]**과 **[모바일 인증기 코드 생성]**을 양방향 대시보드 형태로 구성했습니다.
   - 실제 스마트폰 Google Authenticator / Microsoft Authenticator 앱과 번호가 오차 없이 일치하는지 한눈에 직관적으로 비교할 수 있는 UI를 설계했습니다.

3. **구현 중 직면했던 문제와 해결**:
   - **문제**: RFC 6238 표준에 따라 30초 단위 카운터 $T$를 8바이트 Big-Endian 버퍼로 정확히 변환하고, HMAC-SHA1 결과의 19번째 바이트 하위 4비트로 오프셋을 구하는 **동적 절단(Dynamic Truncation)** 연산이 조금만 어긋나도 스마트폰 앱과 코드가 불일치하는 문제가 발생할 수 있었습니다.
   - **해결**: RFC 6238 Appendix B의 공식 테스트 벡터($T=59\text{s}$, $1111111109\text{s}$, $1234567890\text{s}$, $2000000000\text{s}$)를 기반으로 유닛 테스트 코드를 작성해 100% 일치함을 검증한 뒤 앱에 연동했습니다.

---

## 🛡️ TOTP 원리 및 보안 점검 (사이버보안과 체크포인트)

### 1. `Math.random()` 대신 `crypto.getRandomValues()`를 사용해야 하는 이유
- `Math.random()`은 암호학적으로 취약한 의사난수 생성기(PRNG)로, 내부 상태가 작고 선형 합동 생성기(LCG) 등을 기반으로 하여 몇 번의 출력 패턴만으로도 다음 시퀀스를 공격자가 역추적(Seed Reconstruction)할 수 있습니다.
- 반면 `window.crypto.getRandomValues()`는 운영체제 커널의 하드웨어 인터럽트, 마우스 움직임 등의 엔트로피 풀을 사용하는 **CSPRNG(Cryptographically Secure Pseudo-Random Number Generator)**이므로, 공격자가 비밀 키를 사전 예측하거나 무차별 대입하는 공격을 원천 방어합니다.

### 2. 브라우저(Web Crypto API / `crypto.subtle`) 로컬 처리의 보안상 이점 (Zero-Transmission)
- **비밀 키 유출 원천 차단**: 비밀 키 생성 및 HMAC-SHA1 해시 연산이 브라우저의 로컬 샌드박스 내부(`crypto.subtle`)에서만 처리되며 외부 서버 API로 단 1바이트도 전송되지 않습니다. 따라서 중간자 공격(MITM), 네트워크 도청, 서버 데이터베이스 탈취로부터 안전합니다.
- **개발자 도구(F12) Network 탭 확인**: 키 발급, 30초 주기 코드 갱신, 2FA 검증 전 과정에서 외부 백엔드로 전송되는 네트워크 요청 건수가 **`0건`**임을 직접 확인했습니다.

### 3. 스마트폰 Authenticator 앱과의 실시간 일치 원리
- 스마트폰 Google Authenticator / Microsoft Authenticator 앱으로 웹 화면의 QR 코드를 스캔했을 때, PC 웹앱의 6자리 숫자와 스마트폰 화면의 번호가 **완벽히 일치**합니다.
- 이는 두 장치가 인터넷 통신을 하지 않더라도, 사전에 공유된 동일한 Base32 비밀키($K$)와 전 세계 표준 Unix 시간($T = \lfloor \text{Time} / 30 \rfloor$)을 기반으로 표준 HMAC-SHA1 연산을 독립적으로 수행하기 때문입니다.

---

## 🚀 실행 및 배포 링크

- **GitHub Pages 배포 URL**: [https://jjkjsjjkjsjjkjs-boop.github.io/26-w11-mobile-otp/](https://jjkjsjjkjsjjkjs-boop.github.io/26-w11-mobile-otp/)
- **Netlify 배포 URL**: `https://<내-사이트이름>.netlify.app` *(Netlify 콘솔에서 저장소 연동 후 생성)*

---

## 💡 나만의 확장 기능

1. **다중 계정 관리 (Multi-Account Support)**:
   - 기본 연동 계정 외에도 사용자가 GitHub 2FA, AWS, Naver 등 추가 서비스의 계정과 비밀키를 등록하고 삭제할 수 있는 모바일 인증기 계정 관리 기능을 지원합니다.
2. **원클릭 빠른 검증 연동 (Quick-Fill Verification)**:
   - 모바일 인증기에 뜬 6자리 코드를 클릭 한 번으로 좌측 2단계 로그인 검증창에 즉시 입력하고 검증하는 편의 기능을 제공합니다.
3. **시간 오차 드리프트 윈도우 (±30초 허용 토글)**:
   - 사용자와 서버 기기 간 미세한 시계 오차(Clock Drift)를 수용할 수 있도록 $\pm 1$ 스텝(앞뒤 30초) 시간 오차 허용 옵션 및 최근 검증 이력(성공/실패 시간차) 로깅을 구현했습니다.
4. **사이버보안 암호화 파이프라인 분석실 (RFC 6238 Visualizer)**:
   - Base32 디코딩 $\to$ 8바이트 Big-Endian 타임 카운터 $\to$ HMAC-SHA1 해시 다이제스트 $\to$ Dynamic Truncation 오프셋 및 4바이트 추출 $\to$ Modulo $10^6$ 최종 6자리 도출의 5단계를 실시간 시각화하여 보안 학습 효과를 극대화했습니다.
