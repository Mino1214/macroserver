-- cursor-spec 마켓 스키마 참고용 (실제 적용은 server.js runMigrations + market/dbMigrate.js)

-- users / mu_users 확장은 dbMigrate에서 SHOW COLUMNS 로 조건부 ALTER

-- 주요 신규 테이블: market_points, market_cash_balance, market_cash_transactions,
-- market_point_convert_policy, market_attendance, market_videos, market_mini_game_logs,
-- market_products, market_orders, market_refresh_tokens
