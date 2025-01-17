import time
from flask import Blueprint, request
from werkzeug.security import generate_password_hash, check_password_hash
from server.app.utils.decorators import token_required
from server.app.utils.diskcache_lock import diskcache_lock
from server.app.utils.sqlite_client import get_db_connection
from server.app.utils.token_helper import TokenHelper
from server.logger.logger_config import my_logger as logger

account_bp = Blueprint('account_config',
                       __name__,
                       url_prefix='/open_kf_api/account')


@account_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    account_name = data.get('account_name')
    password = data.get('password')

    if not account_name or not password:
        return {
            'retcode': -20000,
            'message': '账号和密码都需要正确填写！！',
            'data': {}
        }

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the account exists and verify the password
        cur.execute(
            'SELECT id, password_hash FROM t_account_tab WHERE account_name = ?',
            (account_name, ))
        account = cur.fetchone()

        if account and check_password_hash(account['password_hash'], password):
            # Generate token with account_name in the payload
            token = TokenHelper.generate_token(account_name)
            logger.info(f"生成token: '{token}'")

            # Set is_login to 1 and update mtime to the current Unix timestamp
            try:
                with diskcache_lock.lock():
                    cur.execute(
                        'UPDATE t_account_tab SET is_login = 1, mtime = ? WHERE account_name = ?',
                        (
                            int(time.time()),
                            account_name,
                        ))
                    conn.commit()
            except Exception as e:
                logger.error(f"进程获取锁异常: {e}")
                return {
                    'retcode': -30000,
                    'message': f'发生错误: {e}',
                    'data': {}
                }

            return {
                'retcode': 0,
                'message': '登录成功！',
                'data': {
                    'token': token
                }
            }
        else:
            return {
                'retcode': -20001,
                'message': '无效的账号',
                'data': {}
            }
    except Exception as e:
        return {
            'retcode': -30000,
            'message': f'登陆的时候发生错误，信息如下: {e}',
            'data': {}
        }
    finally:
        if conn:
            conn.close()


@account_bp.route('/update_password', methods=['POST'])
@token_required
def update_password():
    data = request.json
    account_name = data.get('account_name')
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if None in (account_name, current_password, new_password):
        return {
            'retcode': -20000,
            'message':
            '账号名称，当前密码以及新密码都需要填写',
            'data': {}
        }

    token_user_id = request.user_payload['user_id']
    if token_user_id != account_name:
        logger.error(
            f"account_name:'{account_name}' does not match with token_user_id: '{token_user_id}'"
        )
        return {'retcode': -20001, 'message': 'Token is invalid!', 'data': {}}

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the account exists and verify the current password
        cur.execute(
            'SELECT id, password_hash FROM t_account_tab WHERE account_name = ?',
            (account_name, ))
        account = cur.fetchone()

        if not account or not check_password_hash(account['password_hash'],
                                                  current_password):
            logger.error(
                f"Invalid account_name: '{account_name}' or current_password: '{current_password}'"
            )
            return {
                'retcode': -20001,
                'message': 'Invalid account name or password',
                'data': {}
            }

        # Update the password
        new_password_hash = generate_password_hash(new_password,
                                                   method='pbkdf2:sha256',
                                                   salt_length=10)
        try:
            with diskcache_lock.lock():
                cur.execute(
                    'UPDATE t_account_tab SET password_hash = ?, mtime = ? WHERE account_name = ?',
                    (
                        new_password_hash,
                        int(time.time()),
                        account_name,
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Process discache_lock exception: {e}")
            return {
                'retcode': -30000,
                'message': f'An error occurred: {e}',
                'data': {}
            }

        return {
            'retcode': 0,
            'message': 'Password updated successfully',
            'data': {}
        }
    except Exception as e:
        return {
            'retcode': -20001,
            'message': f'An error occurred: {e}',
            'data': {}
        }
    finally:
        if conn:
            conn.close()
