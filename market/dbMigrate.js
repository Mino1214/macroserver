/**
 * cursor-spec 기반 마켓 플랫폼 테이블 (MariaDB)
 */

const SAFE_TABLE = /^[a-zA-Z0-9_]+$/;
async function columnExists(pool, table, col) {
  if (!SAFE_TABLE.test(table) || !SAFE_TABLE.test(col)) return false;
  const [rows] = await pool.query(`SHOW COLUMNS FROM \`${table}\` LIKE ?`, [col]);
  return rows.length > 0;
}

async function runMarketMigrations(pool) {
  // users 테넌시·상태
  try {
    if (!(await columnExists(pool, 'users', 'operator_mu_user_id'))) {
      await pool.query(
        'ALTER TABLE users ADD COLUMN operator_mu_user_id INT NULL DEFAULT NULL COMMENT \'소속 운영자 mu_users.id\'',
      );
      await pool.query('ALTER TABLE users ADD INDEX idx_users_operator_mu (operator_mu_user_id)');
      console.log('[market DB] users.operator_mu_user_id 추가');
    }
  } catch (e) {
    console.error('[market DB] users.operator_mu_user_id:', e.message);
  }

  try {
    if (!(await columnExists(pool, 'users', 'market_status'))) {
      await pool.query(
        "ALTER TABLE users ADD COLUMN market_status ENUM('active','suspended') NOT NULL DEFAULT 'active'",
      );
      console.log('[market DB] users.market_status 추가');
    }
  } catch (e) {
    console.error('[market DB] users.market_status:', e.message);
  }

  // mu_users: 운영자/마스터(선택) 마켓 메타
  try {
    if (!(await columnExists(pool, 'mu_users', 'market_role'))) {
      await pool.query(
        'ALTER TABLE mu_users ADD COLUMN market_role VARCHAR(20) NULL DEFAULT NULL COMMENT \'master|operator\'',
      );
      console.log('[market DB] mu_users.market_role 추가');
    }
  } catch (e) {
    console.error('[market DB] mu_users.market_role:', e.message);
  }
  try {
    if (!(await columnExists(pool, 'mu_users', 'site_domain'))) {
      await pool.query(
        'ALTER TABLE mu_users ADD COLUMN site_domain VARCHAR(255) NULL DEFAULT NULL',
      );
      console.log('[market DB] mu_users.site_domain 추가');
    }
  } catch (e) {
    console.error('[market DB] mu_users.site_domain:', e.message);
  }
  try {
    if (!(await columnExists(pool, 'mu_users', 'is_site_active'))) {
      await pool.query(
        'ALTER TABLE mu_users ADD COLUMN is_site_active TINYINT(1) NOT NULL DEFAULT 0',
      );
      console.log('[market DB] mu_users.is_site_active 추가');
    }
  } catch (e) {
    console.error('[market DB] mu_users.is_site_active:', e.message);
  }
  try {
    const [idx] = await pool.query(
      "SHOW INDEX FROM mu_users WHERE Key_name = 'idx_mu_users_site_domain'",
    );
    if (idx.length === 0) {
      await pool.query('CREATE INDEX idx_mu_users_site_domain ON mu_users (site_domain)');
    }
  } catch (e) {
    console.warn('[market DB] mu_users site_domain index:', e.message);
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_points (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      amount INT NOT NULL,
      type VARCHAR(30) NOT NULL,
      description VARCHAR(255) DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_market_points_user (user_id),
      INDEX idx_market_points_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_cash_balance (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL UNIQUE,
      balance INT NOT NULL DEFAULT 0,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_market_cash_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_cash_transactions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      amount INT NOT NULL,
      type VARCHAR(30) NOT NULL,
      description VARCHAR(255) DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_mct_user_time (user_id, created_at),
      INDEX idx_mct_type (type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_point_convert_policy (
      id INT AUTO_INCREMENT PRIMARY KEY,
      operator_mu_user_id INT NULL DEFAULT NULL,
      monthly_limit INT NOT NULL DEFAULT 50000,
      convert_rate DECIMAL(5,2) NOT NULL DEFAULT 1.00,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_policy_operator_mu (operator_mu_user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_attendance (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      checked_date DATE NOT NULL,
      points_earned INT NOT NULL DEFAULT 100,
      streak_count INT NOT NULL DEFAULT 1,
      UNIQUE KEY uq_market_attendance_user_date (user_id, checked_date),
      INDEX idx_market_att_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_videos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      file_url VARCHAR(500) NOT NULL,
      thumbnail_url VARCHAR(500) DEFAULT NULL,
      title VARCHAR(200) DEFAULT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      review_stage VARCHAR(20) NOT NULL DEFAULT 'operator',
      points_earned INT NOT NULL DEFAULT 0,
      reviewed_by_mu_user_id INT NULL DEFAULT NULL,
      reviewed_at DATETIME NULL DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_market_vid_user (user_id),
      INDEX idx_market_vid_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_mini_game_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      game_type VARCHAR(50) NOT NULL,
      score INT NOT NULL DEFAULT 0,
      points_earned INT NOT NULL,
      played_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_mmg_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_products (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(200) NOT NULL,
      description TEXT,
      category VARCHAR(50) DEFAULT NULL,
      operator_mu_user_id INT NULL DEFAULT NULL,
      price_cash INT NOT NULL DEFAULT 0,
      stock INT NOT NULL DEFAULT -1,
      is_visible TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_market_prod_operator (operator_mu_user_id),
      INDEX idx_market_prod_visible (is_visible)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_orders (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      product_id INT NOT NULL,
      operator_mu_user_id INT NULL DEFAULT NULL,
      quantity INT NOT NULL DEFAULT 1,
      total_cash INT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_mord_user (user_id),
      INDEX idx_mord_operator (operator_mu_user_id),
      INDEX idx_mord_product (product_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_refresh_tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      token_hash VARCHAR(64) NOT NULL UNIQUE,
      subject_type VARCHAR(20) NOT NULL,
      users_id VARCHAR(50) NULL,
      mu_user_id INT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_mrt_expires (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  // 기본 전역 정책 (operator NULL 대신 0 행 — id=1 operator_mu_user_id NULL)
  try {
    const [[cnt]] = await pool.query('SELECT COUNT(*) AS c FROM market_point_convert_policy');
    if (Number(cnt.c) === 0) {
      await pool.query(
        'INSERT INTO market_point_convert_policy (operator_mu_user_id, monthly_limit, convert_rate) VALUES (NULL, 50000, 1.00)',
      );
      console.log('[market DB] 기본 point_convert_policy 삽입');
    }
  } catch (e) {
    console.warn('[market DB] policy seed:', e.message);
  }

  console.log('[market DB] 마이그레이션 완료');
}

module.exports = { runMarketMigrations };
