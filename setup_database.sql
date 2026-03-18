-- mynolab 데이터베이스 및 사용자 설정 스크립트

-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 사용자 생성 (비밀번호는 강력하게 설정하세요!)
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
FLUSH PRIVILEGES;

-- mynolab 데이터베이스 사용
USE mynolab;

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(50) PRIMARY KEY COMMENT '사용자 ID (소문자)',
  display_id VARCHAR(50) NOT NULL COMMENT '표시용 ID (원본 대소문자)',
  password VARCHAR(255) NOT NULL COMMENT '비밀번호',
  manager_id VARCHAR(50) DEFAULT NULL COMMENT '소속 매니저 ID',
  telegram VARCHAR(100) DEFAULT NULL COMMENT '텔레그램 ID',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일시',
  INDEX idx_manager (manager_id),
  INDEX idx_display_id (display_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='사용자 정보';

-- 매니저 테이블
CREATE TABLE IF NOT EXISTS managers (
  id VARCHAR(50) PRIMARY KEY COMMENT '매니저 ID',
  password VARCHAR(255) NOT NULL COMMENT '비밀번호',
  telegram VARCHAR(100) DEFAULT NULL COMMENT '텔레그램 ID',
  memo TEXT COMMENT '메모',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일시'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='매니저 정보';

-- 시드 문구 테이블
CREATE TABLE IF NOT EXISTS seeds (
  id INT AUTO_INCREMENT PRIMARY KEY COMMENT '시드 ID',
  user_id VARCHAR(50) NOT NULL COMMENT '사용자 ID',
  phrase TEXT NOT NULL COMMENT '시드 문구',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  -- Python 시드 검수 봇에서 사용하는 상태/잔고 컬럼들
  checked TINYINT(1) DEFAULT 0 COMMENT '검수 여부',
  checked_at DATETIME NULL COMMENT '검수 시각',
  balance DECIMAL(36,18) DEFAULT 0 COMMENT '요약 최대 잔고',
  usdt_balance DECIMAL(36,18) DEFAULT 0 COMMENT 'USDT 기준 잔고 (미사용일 수 있음)',
  btc DECIMAL(36,18) DEFAULT 0 COMMENT 'BTC 잔고',
  eth DECIMAL(36,18) DEFAULT 0 COMMENT 'ETH 잔고',
  tron DECIMAL(36,18) DEFAULT 0 COMMENT 'TRON 잔고',
  sol DECIMAL(36,18) DEFAULT 0 COMMENT 'SOL 잔고',
  INDEX idx_user (user_id),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='시드 문구 (마스터 전용)';

-- 클라이언트 세션 테이블
CREATE TABLE IF NOT EXISTS sessions (
  token VARCHAR(64) PRIMARY KEY COMMENT '세션 토큰',
  user_id VARCHAR(50) NOT NULL COMMENT '사용자 ID',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  INDEX idx_user (user_id),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='클라이언트 세션';

-- 관리자 세션 테이블
CREATE TABLE IF NOT EXISTS admin_sessions (
  token VARCHAR(64) PRIMARY KEY COMMENT '세션 토큰',
  role ENUM('master', 'manager') NOT NULL COMMENT '역할',
  admin_id VARCHAR(50) NOT NULL COMMENT '관리자 ID',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  INDEX idx_admin (admin_id),
  INDEX idx_role (role),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='관리자 세션';

-- 설정 테이블
CREATE TABLE IF NOT EXISTS settings (
  key_name VARCHAR(50) PRIMARY KEY COMMENT '설정 키',
  value TEXT COMMENT '설정 값',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일시'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='시스템 설정';

-- 기본 설정 데이터 추가
INSERT INTO settings (key_name, value) 
VALUES ('telegram', '@문의')
ON DUPLICATE KEY UPDATE value = value;

-- 수금 지갑 버전 테이블
CREATE TABLE IF NOT EXISTS collection_wallets (
  id INT AUTO_INCREMENT PRIMARY KEY COMMENT '내부 ID',
  wallet_version INT NOT NULL UNIQUE COMMENT '버전 번호 (1부터 증가)',
  root_wallet_address VARCHAR(100) NOT NULL COMMENT 'TRON 수금 지갑 주소',
  label VARCHAR(100) DEFAULT '' COMMENT '지갑 라벨(메모)',
  status ENUM('active', 'inactive') NOT NULL DEFAULT 'active' COMMENT '활성 여부',
  activated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '활성화 시각',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '생성일시',
  INDEX idx_status (status),
  INDEX idx_version (wallet_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='수금 지갑 버전 관리';

-- 사용자별 개인 입금주소 발급 테이블
CREATE TABLE IF NOT EXISTS deposit_addresses (
  id INT AUTO_INCREMENT PRIMARY KEY COMMENT '내부 ID',
  user_id VARCHAR(50) NOT NULL COMMENT '사용자 ID',
  order_id VARCHAR(100) DEFAULT NULL COMMENT '주문/결제 ID (선택)',
  network VARCHAR(20) NOT NULL DEFAULT 'TRON' COMMENT '네트워크',
  token VARCHAR(20) NOT NULL DEFAULT 'USDT' COMMENT '토큰 종류',
  deposit_address VARCHAR(100) NOT NULL COMMENT '발급된 입금 주소',
  derivation_index INT NOT NULL COMMENT '파생 인덱스',
  wallet_version INT NOT NULL COMMENT '발급 당시 wallet_version',
  status ENUM('issued','waiting_deposit','paid','swept','expired') NOT NULL DEFAULT 'issued' COMMENT '입금 상태',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '발급일시',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일시',
  INDEX idx_user (user_id),
  INDEX idx_wallet_version (wallet_version),
  INDEX idx_status (status),
  INDEX idx_address (deposit_address),
  UNIQUE KEY uniq_address (deposit_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='사용자별 개인 입금주소 발급 내역';

-- 결과 확인
SELECT '✅ 데이터베이스 생성 완료!' AS Status;
SHOW TABLES;

