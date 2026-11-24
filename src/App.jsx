import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Smartphone,
  RefreshCw,
  Copy,
  Check,
  Lock,
  Laptop,
  ArrowRight,
  UserCheck,
  Plus,
  Trash2,
  Cpu,
  Terminal,
  Shield,
  Eye,
  EyeOff,
  Sparkles,
} from 'lucide-react';
import {
  generateBase32Secret,
  generateTotpWithTrace,
  generateTotp,
  verifyTotp,
  buildOtpAuthUri,
} from './utils/totp';
import './App.css';

export default function App() {
  // --- State: Service Provider Configuration (Left Panel) ---
  const [issuer, setIssuer] = useState('CyberSec Portal');
  const [account, setAccount] = useState('student@kopo.ac.kr');
  const [secret, setSecret] = useState(() => generateBase32Secret(32));
  const [showSecret, setShowSecret] = useState(false);

  // --- State: Mobile Authenticator Simulator (Right Panel) ---
  const [customAccounts, setCustomAccounts] = useState([
    {
      id: 'github',
      issuer: 'GitHub 2FA',
      account: 'security-admin',
      secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      isPrimary: false,
      color: '#10b981',
    },
  ]);

  const primaryAccount = useMemo(
    () => ({
      id: 'primary',
      issuer,
      account,
      secret,
      isPrimary: true,
      color: '#3b82f6',
    }),
    [issuer, account, secret]
  );

  const accounts = useMemo(
    () => [primaryAccount, ...customAccounts],
    [primaryAccount, customAccounts]
  );

  const [accountCodes, setAccountCodes] = useState({});
  const [newAccountModal, setNewAccountModal] = useState(false);
  const [newIssuer, setNewIssuer] = useState('');
  const [newAccountName, setNewAccountName] = useState('');
  const [newSecretKey, setNewSecretKey] = useState('');

  // --- State: Primary Trace & Timer ---
  const [now, setNow] = useState(() => Date.now());
  const [trace, setTrace] = useState(null);

  // --- State: 2FA Verification (Left Panel) ---
  const [inputOtp, setInputOtp] = useState('');
  const [allowWindowDrift, setAllowWindowDrift] = useState(true);
  const [verificationResult, setVerificationResult] = useState(null);
  const [verifyHistory, setVerifyHistory] = useState([]);

  // --- State: Toast & UI ---
  const [toastMessage, setToastMessage] = useState(null);
  const [activeInspectorTab, setActiveInspectorTab] = useState('pipeline');

  // Trigger Toast Notification
  const showToast = useCallback((msg) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 2200);
  }, []);

  // Copy to clipboard helper
  const handleCopy = useCallback(
    (text, label = '클립보드에') => {
      navigator.clipboard.writeText(text).then(
        () => showToast(`${label} 복사되었습니다!`),
        () => showToast('복사에 실패했습니다.')
      );
    },
    [showToast]
  );

  // Master Timer: Tick every second
  useEffect(() => {
    const interval = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Compute Primary Trace & Codes for all accounts whenever 'now' or secrets change
  useEffect(() => {
    let isCancelled = false;

    // Compute primary trace
    generateTotpWithTrace(secret, now)
      .then((t) => {
        if (!isCancelled) setTrace(t);
      })
      .catch((err) => console.error('Trace error:', err));

    // Compute OTP for all accounts
    Promise.all(
      accounts.map(async (acc) => {
        try {
          const code = await generateTotp(acc.secret, now);
          return [acc.id, code];
        } catch {
          return [acc.id, '------'];
        }
      })
    ).then((results) => {
      if (!isCancelled) {
        setAccountCodes(Object.fromEntries(results));
      }
    });

    return () => {
      isCancelled = true;
    };
  }, [now, secret, accounts]);

  // Regenerate New Secret Key for Service
  const handleRegenerateSecret = useCallback(() => {
    const newSec = generateBase32Secret(32);
    setSecret(newSec);
    setVerificationResult(null);
    setInputOtp('');
    showToast('새로운 Base32 비밀 키(CSPRNG)가 생성되었습니다.');
  }, [showToast]);

  // Built OTP Auth URI
  const otpAuthUri = useMemo(() => {
    return buildOtpAuthUri({
      issuer,
      account,
      secret,
    });
  }, [issuer, account, secret]);

  // Handle 2FA Verification
  const handleVerify = useCallback(
    async (codeToTest = inputOtp) => {
      const cleanCode = codeToTest.trim().replace(/\s+/g, '');
      if (!cleanCode) {
        setVerificationResult({
          success: false,
          message: '6자리 인증 번호를 입력해 주세요.',
        });
        return;
      }

      const windowValue = allowWindowDrift ? 1 : 0;
      const res = await verifyTotp(cleanCode, secret, {
        window: windowValue,
        timeMs: now,
      });

      const timestampStr = new Date().toLocaleTimeString('ko-KR');

      if (res.valid) {
        let note = '현재 30초 시간대와 정확히 일치';
        if (res.delta === -1) note = '이전 30초(-30s) 허용 범위 일치';
        if (res.delta === 1) note = '다음 30초(+30s) 허용 범위 일치';

        const resultObj = {
          success: true,
          code: cleanCode,
          delta: res.delta,
          message: `인증 성공! (${note})`,
          timestamp: timestampStr,
        };
        setVerificationResult(resultObj);
        setVerifyHistory((prev) => [resultObj, ...prev.slice(0, 4)]);
        showToast('인증 성공: 정상 승인되었습니다.');
      } else {
        const resultObj = {
          success: false,
          code: cleanCode,
          delta: null,
          message: '인증 실패: 6자리 번호가 일치하지 않거나 만료되었습니다.',
          timestamp: timestampStr,
        };
        setVerificationResult(resultObj);
        setVerifyHistory((prev) => [resultObj, ...prev.slice(0, 4)]);
      }
    },
    [inputOtp, secret, allowWindowDrift, now, showToast]
  );

  // Quick fill OTP code from Authenticator to Login input
  const handleQuickFill = useCallback(
    (code) => {
      setInputOtp(code);
      handleVerify(code);
    },
    [handleVerify]
  );

  // Add Custom Account to Authenticator
  const handleAddAccount = (e) => {
    e.preventDefault();
    const cleanSec = newSecretKey.toUpperCase().replace(/[\s-]/g, '');
    if (!newIssuer || !newAccountName || !cleanSec) {
      showToast('모든 항목을 입력해 주세요.');
      return;
    }
    const newAcc = {
      id: 'acc_' + Date.now(),
      issuer: newIssuer,
      account: newAccountName,
      secret: cleanSec,
      isPrimary: false,
      color: '#8b5cf6',
    };
    setCustomAccounts((prev) => [...prev, newAcc]);
    setNewAccountModal(false);
    setNewIssuer('');
    setNewAccountName('');
    setNewSecretKey('');
    showToast('새 인증 계정이 모바일에 추가되었습니다.');
  };

  // Remove Account
  const handleRemoveAccount = (id) => {
    setCustomAccounts((prev) => prev.filter((acc) => acc.id !== id));
    showToast('계정이 삭제되었습니다.');
  };

  const remainingSeconds = trace?.remainingSeconds ?? 30;
  const progressRatio = remainingSeconds / 30;
  const isExpiringSoon = remainingSeconds <= 5;

  return (
    <div className="otp-studio-app">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="otp-toast-banner" role="status">
          <Check size={18} className="toast-icon" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header */}
      <header className="otp-header">
        <div className="header-brand">
          <div className="brand-icon-wrapper">
            <Lock className="brand-icon" size={26} />
          </div>
          <div>
            <h1 className="brand-title">CyberOTP Studio</h1>
            <p className="brand-subtitle">
              RFC 6238 기반 모바일 OTP & 2단계 인증 시뮬레이터 (Zero-Transmission)
            </p>
          </div>
        </div>

        {/* Security Audit Badges */}
        <div className="security-badges-container">
          <div className="sec-badge sec-badge-success" title="외부 API 호출 0건, 브라우저 로컬 암호화">
            <ShieldCheck size={16} />
            <span>Zero-Transmission</span>
          </div>
          <div className="sec-badge sec-badge-purple" title="브라우저 내장 crypto.subtle HMAC-SHA1">
            <Cpu size={16} />
            <span>Web Crypto API</span>
          </div>
          <div className="sec-badge sec-badge-blue" title="crypto.getRandomValues 암호학적 안전 난수">
            <KeyRound size={16} />
            <span>CSPRNG</span>
          </div>
        </div>
      </header>

      {/* Main Dual View Grid */}
      <main className="otp-main-grid">
        {/* ============================================================== */}
        {/* LEFT PANEL: 2FA Authentication Service / Login Simulator      */}
        {/* ============================================================== */}
        <section className="studio-card service-card" aria-labelledby="service-panel-heading">
          <div className="card-header">
            <div className="card-title-group">
              <Laptop size={22} className="card-header-icon service-icon" />
              <div>
                <h2 id="service-panel-heading" className="card-title">
                  2FA 로그인 인증 서버
                </h2>
                <p className="card-desc">웹 서비스 관점에서 비밀키를 발급하고 2단계 인증을 검증합니다.</p>
              </div>
            </div>
            <span className="panel-tag service-tag">Service Provider</span>
          </div>

          <div className="card-body">
            {/* Step 1: Account Configuration */}
            <div className="setup-section">
              <div className="section-label-row">
                <span className="step-badge">1</span>
                <span className="section-heading">서비스 및 계정 정보</span>
              </div>
              <div className="input-grid">
                <div className="form-group">
                  <label htmlFor="service-issuer">발급자 (Issuer)</label>
                  <input
                    id="service-issuer"
                    type="text"
                    className="styled-input"
                    value={issuer}
                    onChange={(e) => setIssuer(e.target.value)}
                    placeholder="예: CyberSec Portal"
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="service-account">사용자 계정 (Account)</label>
                  <input
                    id="service-account"
                    type="text"
                    className="styled-input"
                    value={account}
                    onChange={(e) => setAccount(e.target.value)}
                    placeholder="예: student@kopo.ac.kr"
                  />
                </div>
              </div>

              {/* Secret Key Box */}
              <div className="secret-key-box">
                <div className="secret-header-row">
                  <span className="secret-label">
                    <KeyRound size={14} /> Base32 비밀 키 (Secret Key)
                  </span>
                  <div className="secret-actions">
                    <button
                      type="button"
                      className="icon-action-btn"
                      onClick={() => setShowSecret(!showSecret)}
                      title={showSecret ? '비밀키 숨기기' : '비밀키 보기'}
                    >
                      {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                    <button
                      type="button"
                      className="icon-action-btn"
                      onClick={() => handleCopy(secret, '비밀 키가')}
                      title="비밀키 복사"
                    >
                      <Copy size={15} />
                    </button>
                    <button
                      type="button"
                      className="btn-regenerate"
                      onClick={handleRegenerateSecret}
                      title="crypto.getRandomValues로 새 키 발급"
                    >
                      <RefreshCw size={13} /> 새 비밀키 발급
                    </button>
                  </div>
                </div>
                <div className="secret-value-display font-mono">
                  {showSecret
                    ? secret.match(/.{1,4}/g)?.join(' ') || secret
                    : '•••• •••• •••• •••• •••• •••• •••• ••••'}
                </div>
              </div>
            </div>

            {/* Step 2: QR Code */}
            <div className="setup-section qr-section">
              <div className="section-label-row">
                <span className="step-badge">2</span>
                <span className="section-heading">스마트폰 Authenticator QR 연동</span>
              </div>
              <div className="qr-content-wrapper">
                <div className="qr-code-frame" title="스마트폰으로 스캔하세요">
                  <QRCodeSVG
                    value={otpAuthUri}
                    size={170}
                    level="M"
                    includeMargin={true}
                    aria-label="TOTP QR Code"
                  />
                </div>
                <div className="qr-instruction-box">
                  <p className="qr-guide-text">
                    📱 <strong>스마트폰 카메라 또는 Authenticator 앱</strong>(Google OTP, Microsoft Authenticator, 2FAS 등)으로 이 QR을 스캔하세요.
                  </p>
                  <ul className="qr-checklist">
                    <li>인터넷 연결 없이도 스마트폰과 PC가 똑같이 30초마다 갱신됩니다.</li>
                    <li>QR 스캔 후 스마트폰 화면에 뜨는 6자리를 아래 검증창에 입력해 보세요.</li>
                  </ul>
                  <div className="qr-uri-copy-row">
                    <button
                      type="button"
                      className="text-btn"
                      onClick={() => handleCopy(otpAuthUri, 'otpauth URI가')}
                    >
                      <Copy size={13} /> otpauth:// URI 주소 복사
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 3: Verification */}
            <div className="setup-section verification-section">
              <div className="section-label-row">
                <span className="step-badge">3</span>
                <span className="section-heading">2단계 인증 번호 검증 (2FA Verification)</span>
              </div>

              <form
                className="verify-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  handleVerify();
                }}
              >
                <div className="verify-input-row">
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    className="styled-input otp-large-input font-mono"
                    placeholder="6자리 입력 (예: 123456)"
                    value={inputOtp}
                    onChange={(e) => setInputOtp(e.target.value.replace(/[^0-9]/g, ''))}
                  />
                  <button type="submit" className="btn-primary verify-btn">
                    <UserCheck size={18} /> 인증 검증
                  </button>
                </div>

                <div className="verify-options-row">
                  <label className="checkbox-label" title="클록 오차를 감안해 앞뒤 30초 허용">
                    <input
                      type="checkbox"
                      checked={allowWindowDrift}
                      onChange={(e) => setAllowWindowDrift(e.target.checked)}
                    />
                    <span>시간 오차 허용 (±30초 Drift Window)</span>
                  </label>
                  {trace && (
                    <span className="expected-otp-hint">
                      (실시간 예상 OTP: <strong className="font-mono">{trace.otp}</strong>)
                    </span>
                  )}
                </div>
              </form>

              {/* Verification Feedback Banner */}
              {verificationResult && (
                <div
                  className={`verify-result-banner ${
                    verificationResult.success ? 'result-success' : 'result-failed'
                  }`}
                  role="alert"
                >
                  {verificationResult.success ? (
                    <ShieldCheck size={20} className="result-icon" />
                  ) : (
                    <ShieldAlert size={20} className="result-icon" />
                  )}
                  <div className="result-text-group">
                    <p className="result-title">
                      {verificationResult.success ? '2단계 인증 승인 완료' : '인증 불일치'}
                    </p>
                    <p className="result-sub">{verificationResult.message}</p>
                  </div>
                </div>
              )}

              {/* Recent Verification History */}
              {verifyHistory.length > 0 && (
                <div className="verify-history-box">
                  <span className="history-heading">최근 인증 시도 기록</span>
                  <div className="history-list">
                    {verifyHistory.map((item, idx) => (
                      <div key={idx} className="history-item">
                        <span className="font-mono history-time">{item.timestamp}</span>
                        <span className="font-mono history-code">{item.code}</span>
                        <span
                          className={`history-status-badge ${
                            item.success ? 'badge-ok' : 'badge-fail'
                          }`}
                        >
                          {item.success ? '성공' : '실패'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* RIGHT PANEL: Mobile Authenticator Simulator                   */}
        {/* ============================================================== */}
        <section className="studio-card mobile-card" aria-labelledby="mobile-panel-heading">
          <div className="card-header">
            <div className="card-title-group">
              <Smartphone size={22} className="card-header-icon mobile-icon" />
              <div>
                <h2 id="mobile-panel-heading" className="card-title">
                  모바일 인증기 (Authenticator 앱)
                </h2>
                <p className="card-desc">
                  스마트폰의 Google Authenticator / Microsoft Authenticator 동작을 재현합니다.
                </p>
              </div>
            </div>
            <span className="panel-tag mobile-tag">Client App</span>
          </div>

          <div className="card-body mobile-phone-frame">
            {/* Phone Top Notch / Status Bar */}
            <div className="phone-status-bar">
              <span className="phone-time font-mono">
                {new Date(now).toLocaleTimeString('ko-KR', {
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </span>
              <div className="phone-status-icons">
                <span className="offline-badge" title="네트워크 통신 없이 100% 로컬 계산">
                  인터넷 불필요(오프라인)
                </span>
              </div>
            </div>

            {/* Authenticator App Bar */}
            <div className="authenticator-app-bar">
              <div className="app-bar-brand">
                <Shield size={20} className="app-bar-icon" />
                <span className="app-bar-title">인증기 (Authenticator)</span>
              </div>
              <button
                type="button"
                className="add-account-btn"
                onClick={() => setNewAccountModal(true)}
                title="새 계정 수동 추가"
              >
                <Plus size={16} /> 계정 추가
              </button>
            </div>

            {/* Smart Synchronized Notice */}
            <div className="phone-banner-tip">
              <Sparkles size={16} className="tip-icon" />
              <p>
                이 화면의 번호는 <strong>스마트폰 앱에 뜨는 번호와 100% 동일</strong>하게 동기화됩니다.
              </p>
            </div>

            {/* Accounts List in Mobile Authenticator */}
            <div className="phone-accounts-scroll">
              {accounts.map((acc) => {
                const code = accountCodes[acc.id] || '------';
                const formattedCode =
                  code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;

                return (
                  <div
                    key={acc.id}
                    className={`phone-account-card ${acc.isPrimary ? 'primary-account-card' : ''}`}
                  >
                    <div className="acc-card-top">
                      <div className="acc-issuer-group">
                        <span
                          className="acc-color-dot"
                          style={{ backgroundColor: acc.color || '#3b82f6' }}
                        />
                        <span className="acc-issuer-name">{acc.issuer}</span>
                        {acc.isPrimary && <span className="primary-tag">연동 중</span>}
                      </div>

                      <div className="acc-card-actions">
                        {!acc.isPrimary && (
                          <button
                            type="button"
                            className="acc-icon-btn remove-btn"
                            onClick={() => handleRemoveAccount(acc.id)}
                            title="계정 삭제"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="acc-account-name">{acc.account}</div>

                    {/* OTP Display & Timer Row */}
                    <div className="acc-otp-row">
                      <div className="acc-otp-numbers font-mono" title="현재 6자리 일회용 비밀번호">
                        {formattedCode}
                      </div>

                      {/* Circular Timer Visualizer */}
                      <div className="circular-timer-wrapper" title={`${remainingSeconds}초 남음`}>
                        <svg className="timer-svg" viewBox="0 0 36 36">
                          <circle
                            className="timer-circle-bg"
                            cx="18"
                            cy="18"
                            r="15.915"
                            fill="none"
                            strokeWidth="3.5"
                          />
                          <circle
                            className={`timer-circle-fg ${isExpiringSoon ? 'circle-warning' : ''}`}
                            cx="18"
                            cy="18"
                            r="15.915"
                            fill="none"
                            strokeWidth="3.5"
                            strokeDasharray={`${progressRatio * 100}, 100`}
                          />
                        </svg>
                        <span
                          className={`timer-seconds-text font-mono ${
                            isExpiringSoon ? 'seconds-warning' : ''
                          }`}
                        >
                          {remainingSeconds}
                        </span>
                      </div>
                    </div>

                    {/* Quick Action Buttons */}
                    <div className="acc-card-footer">
                      <button
                        type="button"
                        className="pill-action-btn"
                        onClick={() => handleCopy(code, '인증 코드가')}
                      >
                        <Copy size={13} /> 복사
                      </button>

                      {acc.isPrimary && (
                        <button
                          type="button"
                          className="pill-action-btn pill-primary-action"
                          onClick={() => handleQuickFill(code)}
                          title="좌측 로그인 검증창에 즉시 입력하고 검증합니다"
                        >
                          <ArrowRight size={13} /> 2FA 검증창에 입력
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Smart Hint Bar */}
            <div className="phone-bottom-guide">
              <Terminal size={14} />
              <span>동기화 주기: 30초 (RFC 6238 표준 SHA-1)</span>
            </div>
          </div>
        </section>
      </main>

      {/* ============================================================== */}
      {/* BOTTOM SECTION: Cybersecurity Inspector & Audit               */}
      {/* ============================================================== */}
      <section className="studio-card inspector-card" aria-labelledby="inspector-heading">
        <div className="card-header">
          <div className="card-title-group">
            <Cpu size={22} className="card-header-icon inspector-icon" />
            <div>
              <h2 id="inspector-heading" className="card-title">
                사이버보안 분석실 & RFC 6238 암호화 파이프라인
              </h2>
              <p className="card-desc">
                브라우저 내부에서 네트워크 전송 없이(Zero-Transmission) TOTP가 계산되는 과정을 실시간 확인합니다.
              </p>
            </div>
          </div>

          <div className="inspector-tabs">
            <button
              type="button"
              className={`inspector-tab-btn ${activeInspectorTab === 'pipeline' ? 'tab-active' : ''}`}
              onClick={() => setActiveInspectorTab('pipeline')}
            >
              연산 파이프라인
            </button>
            <button
              type="button"
              className={`inspector-tab-btn ${activeInspectorTab === 'security' ? 'tab-active' : ''}`}
              onClick={() => setActiveInspectorTab('security')}
            >
              보안 점검 리포트
            </button>
          </div>
        </div>

        <div className="card-body">
          {activeInspectorTab === 'pipeline' && trace && (
            <div className="pipeline-container">
              <div className="pipeline-grid">
                {/* Step 1: Base32 Decode */}
                <div className="pipeline-step-box">
                  <div className="step-tag">Step 1. 비밀 키 디코딩</div>
                  <div className="step-title">Base32 Secret &rarr; 20 Bytes Key</div>
                  <div className="step-detail-row">
                    <span className="step-field">Base32 Secret:</span>
                    <span className="step-value font-mono">{secret}</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">Hex Raw Key (160-bit):</span>
                    <span className="step-value font-mono break-all">{trace.secretHex}</span>
                  </div>
                </div>

                {/* Step 2: Time Counter */}
                <div className="pipeline-step-box">
                  <div className="step-tag">Step 2. 30초 카운터 버퍼</div>
                  <div className="step-title">T = &lfloor;UnixTime / 30&rfloor; &rarr; 8-Byte Big Endian</div>
                  <div className="step-detail-row">
                    <span className="step-field">현재 UnixTime (초):</span>
                    <span className="step-value font-mono">{trace.epochSeconds} 초</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">카운터 T:</span>
                    <span className="step-value font-mono">{trace.counter}</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">Big-Endian Hex:</span>
                    <span className="step-value font-mono">{trace.counterHex}</span>
                  </div>
                </div>

                {/* Step 3: HMAC-SHA1 */}
                <div className="pipeline-step-box">
                  <div className="step-tag">Step 3. HMAC-SHA1 연산</div>
                  <div className="step-title">crypto.subtle.sign('HMAC', key, T)</div>
                  <div className="step-detail-row">
                    <span className="step-field">알고리즘:</span>
                    <span className="step-value font-mono">HMAC-SHA1 (20 Bytes Output)</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">20-Byte Digest:</span>
                    <span className="step-value font-mono break-all">{trace.hmacHex}</span>
                  </div>
                </div>

                {/* Step 4: Dynamic Truncation */}
                <div className="pipeline-step-box">
                  <div className="step-tag">Step 4. 동적 절단 (RFC 4226)</div>
                  <div className="step-title">Offset = Hash[19] &amp; 0x0F &rarr; 4 Bytes</div>
                  <div className="step-detail-row">
                    <span className="step-field">추출 오프셋 (Offset):</span>
                    <span className="step-value font-mono">{trace.offset} (0x{trace.offset.toString(16)})</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">선택 4바이트 (Hex):</span>
                    <span className="step-value font-mono">{trace.truncatedBinaryHex}</span>
                  </div>
                  <div className="step-detail-row">
                    <span className="step-field">31-bit 마스킹 정수:</span>
                    <span className="step-value font-mono">{trace.truncatedValue}</span>
                  </div>
                </div>

                {/* Step 5: Final OTP Code */}
                <div className="pipeline-step-box step-highlight">
                  <div className="step-tag tag-success">Step 5. 최종 6자리 도출</div>
                  <div className="step-title">Code = Truncated % 10^6</div>
                  <div className="step-detail-row">
                    <span className="step-field">Modulo 1,000,000:</span>
                    <span className="step-value font-mono">{trace.truncatedValue % 1000000}</span>
                  </div>
                  <div className="step-final-code font-mono">
                    {trace.otp}
                  </div>
                  <div className="step-timer-hint">
                    남은 시간: {trace.remainingSeconds}초 (30초마다 자동 재계산)
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeInspectorTab === 'security' && (
            <div className="security-audit-content">
              <div className="audit-card-grid">
                <div className="audit-item">
                  <div className="audit-item-header">
                    <ShieldCheck size={20} className="audit-icon-success" />
                    <h3>1. Math.random() 대신 crypto.getRandomValues() 적용</h3>
                  </div>
                  <p>
                    일반적인 <code>Math.random()</code>은 암호학적으로 취약한 의사난수(PRNG) 생성기로, 연속된 값 패턴을 통해 다음 난수를 역추적(Seed Reconstruction)할 수 있습니다. 본 앱은 브라우저 커널 엔트로피 기반의 <strong>CSPRNG(Cryptographically Secure Pseudo-Random Number Generator)</strong>를 사용하여 예측 불가능한 160-bit 비밀 키를 안전하게 발급합니다.
                  </p>
                </div>

                <div className="audit-item">
                  <div className="audit-item-header">
                    <ShieldCheck size={20} className="audit-icon-success" />
                    <h3>2. Zero-Transmission (무전송) 원칙 검증</h3>
                  </div>
                  <p>
                    개발자 도구(<code>F12</code>)의 <strong>Network 탭</strong>을 열어보세요. 비밀 키 생성 및 HMAC-SHA1 연산 등 모든 암호화 처리가 브라우저 내장 <code>window.crypto.subtle</code> 하드웨어 가속 모듈에서 로컬로 실행되므로 외부 백엔드 서버로 단 1바이트의 비밀 키나 인증 데이터도 전송되지 않습니다.
                  </p>
                </div>

                <div className="audit-item">
                  <div className="audit-item-header">
                    <ShieldCheck size={20} className="audit-icon-success" />
                    <h3>3. 오프라인 동기화의 수학적 원리 (RFC 6238)</h3>
                  </div>
                  <p>
                    스마트폰 Authenticator 앱과 본 웹앱은 서로 어떠한 네트워크 통신도 하지 않습니다. 양쪽이 <strong>동일한 공유 비밀키($K$)</strong>와 전 세계 공통의 <strong>Unix 타임($T = \lfloor \text{Time}/30 \rfloor$)</strong>을 기반으로 독립적으로 동일한 HMAC-SHA1 연산을 수행하기 때문에 완전히 오프라인 상태에서도 정확히 동일한 6자리 숫자가 도출됩니다.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Modal: Add Account */}
      {newAccountModal && (
        <div className="modal-overlay" onClick={() => setNewAccountModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>새 계정 수동 추가</h3>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setNewAccountModal(false)}
              >
                &times;
              </button>
            </div>
            <form onSubmit={handleAddAccount} className="modal-form">
              <div className="form-group">
                <label>서비스/발급자 명 (Issuer)</label>
                <input
                  type="text"
                  required
                  className="styled-input"
                  placeholder="예: AWS Security, Naver"
                  value={newIssuer}
                  onChange={(e) => setNewIssuer(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>계정 식별자 (Account)</label>
                <input
                  type="text"
                  required
                  className="styled-input"
                  placeholder="예: admin@example.com"
                  value={newAccountName}
                  onChange={(e) => setNewAccountName(e.target.value)}
                />
              </div>
              <div className="form-group">
                <div className="modal-secret-label-row">
                  <label>Base32 비밀 키 (Secret)</label>
                  <button
                    type="button"
                    className="text-btn"
                    onClick={() => setNewSecretKey(generateBase32Secret(32))}
                  >
                    랜덤 생성
                  </button>
                </div>
                <input
                  type="text"
                  required
                  className="styled-input font-mono"
                  placeholder="Base32 키 입력 (A-Z, 2-7)"
                  value={newSecretKey}
                  onChange={(e) => setNewSecretKey(e.target.value)}
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setNewAccountModal(false)}
                >
                  취소
                </button>
                <button type="submit" className="btn-primary">
                  계정 등록
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="otp-footer">
        <p>
          모바일 OTP (TOTP RFC 6238) 실습 &bull; 강서 폴리텍 사이버보안과 &bull; Web Crypto API 로컬 암호화
        </p>
      </footer>
    </div>
  );
}
