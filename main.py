"""本地启动入口：uvicorn main:app --reload"""

import os

from app.server import create_app

#: 首次启动时可通过环境变量注入引导管理员密钥；不配置则不创建
ADMIN_KEY = os.environ.get("BOOTSTRAP_ADMIN_KEY")

app = create_app(
    state_path=os.environ.get("AUTH_STATE_PATH", "data/auth_state.json"),
    admin_key=ADMIN_KEY,
)
