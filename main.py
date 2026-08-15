from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
import secrets
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import os

app = FastAPI(title="Tool License API")

DATABASE_URL = os.getenv('DATABASE_URL')

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

download_tokens = {}

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id SERIAL PRIMARY KEY,
            key VARCHAR(20) UNIQUE NOT NULL,
            status VARCHAR(20) DEFAULT 'active',
            expires_at TIMESTAMP,
            used_at TIMESTAMP,
            file_version VARCHAR(20) DEFAULT 'v2.1.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

@app.get("/")
def root():
    return {"status": "API is running", "version": "v2.1.0"}

@app.post("/check_key")
async def check_key(request: dict):
    key = request.get('key', '').upper().strip()
    
    if not key:
        raise HTTPException(status_code=400, detail="Missing key")
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT key, status, expires_at, used_at, file_version
        FROM keys
        WHERE key = %s
    """, (key,))
    
    key_info = cur.fetchone()
    cur.close()
    
    if not key_info:
        conn.close()
        return JSONResponse(
            status_code=400,
            content={"valid": False, "message": "Key không tồn tại!"}
        )
    
    if key_info['status'] != 'active':
        conn.close()
        return JSONResponse(
            status_code=400,
            content={"valid": False, "message": f"Key đã {key_info['status']}!"}
        )
    
    if key_info['expires_at'] and key_info['expires_at'] < datetime.now():
        conn.close()
        return JSONResponse(
            status_code=400,
            content={"valid": False, "message": "Key đã hết hạn!"}
        )
    
    cur = conn.cursor()
    cur.execute("""
        UPDATE keys
        SET status = 'used', used_at = CURRENT_TIMESTAMP
        WHERE key = %s AND status = 'active'
        AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        RETURNING key
    """, (key,))
    
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    if not row:
        return JSONResponse(
            status_code=400,
            content={"valid": False, "message": "Lỗi khi xác nhận key!"}
        )
    
    token = secrets.token_urlsafe(32)
    download_tokens[token] = {
        'key': key,
        'expires_at': datetime.now() + timedelta(minutes=5)
    }
    
    return {
        "valid": True,
        "message": "✅ Key hợp lệ!",
        "token": token,
        "url": f"/download_tool?token={token}",
        "version": key_info.get('file_version', 'v2.1.0')
    }

@app.get("/download_tool")
async def download_tool(token: str):
    if token not in download_tokens:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    token_data = download_tokens[token]
    
    if token_data['expires_at'] < datetime.now():
        del download_tokens[token]
        raise HTTPException(status_code=400, detail="Token đã hết hạn!")
    
    del download_tokens[token]
    
    tool_file = "files/tool_v2.1.0.exe"
    if not os.path.exists(tool_file):
        raise HTTPException(status_code=404, detail="File tool không tồn tại!")
    
    return FileResponse(
        path=tool_file,
        filename="tool.exe",
        media_type="application/octet-stream"
    )

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)