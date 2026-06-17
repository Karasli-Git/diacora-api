"""
Diacora Health - FastAPI Backend
/auth/register, /auth/login, /sync endpoints
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
from typing import Optional, List
import psycopg2
from psycopg2.extras import RealDictCursor

# ============================================================================
# CONFIGURATION
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 saat

app = FastAPI(
    title="Diacora Health API",
    description="Diabetes & Hypertension Management Platform",
    version="1.0.0"
)

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

def get_db():
    """Database bağlantısı al"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        yield conn
        conn.close()
    except Exception as e:
        print(f"❌ Database bağlantı hatası: {e}")
        raise

# ============================================================================
# MODELS
# ============================================================================

class RegisterRequest(BaseModel):
    """Registration istegi"""
    email: EmailStr
    password: str
    name: str
    age: Optional[int] = None
    country_code: str = "TR"
    language: str = "tr"
    diabetes_type: str = "type2"
    has_hypertension: bool = False

class LoginRequest(BaseModel):
    """Login isteği"""
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    """Token yanıtı"""
    access_token: str
    token_type: str = "bearer"
    user_id: str
    name: str
    email: str

class MeasurementData(BaseModel):
    """Ölçüm verisi (Glucose, BP, vb)"""
    measurement_type: str  # "glucose", "blood_pressure", "heart_rate"
    value: float
    unit: str
    measurement_date: datetime
    notes: Optional[str] = None

class MoodData(BaseModel):
    """Ruh hali verisi"""
    emoji: str
    energy_level: int
    stress_level: int
    sleep_hours: Optional[float] = None
    notes: Optional[str] = None

class SyncRequest(BaseModel):
    """iOS'ten sync isteği"""
    user_id: str
    sync_id: str
    measurements: Optional[List[MeasurementData]] = []
    moods: Optional[List[MoodData]] = []
    timestamp: datetime

class SyncResponse(BaseModel):
    """Sync yanıtı"""
    status: str  # "success", "partial", "failed"
    items_synced: int
    message: str

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password: str) -> str:
    """Şifreyi hash'le"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    """Şifreyi doğrula"""
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """JWT token oluştur"""
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    to_encode = {"user_id": user_id, "exp": expire}
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> str:
    """Token doğrula ve user_id döndür"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============================================================================
# ENDPOINTS - HEALTH
# ============================================================================

def init_database():
    """Initialize database tables on startup"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255),
            age INTEGER,
            country_code VARCHAR(5),
            language VARCHAR(10),
            diabetes_type VARCHAR(50),
            has_hypertension BOOLEAN,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Measurements table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS measurements (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            blood_sugar FLOAT,
            blood_pressure_systolic INTEGER,
            blood_pressure_diastolic INTEGER,
            weight FLOAT,
            notes TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Moods table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS moods (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            mood_level INTEGER,
            energy_level INTEGER,
            stress_level INTEGER,
            emoji VARCHAR,
            mood_date DATE,
            notes TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (user_id, mood_date)
        );
        """)
        
        # Medications table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS medications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            medication_name VARCHAR(255),
            dosage VARCHAR(100),
            frequency VARCHAR(100),
            start_date DATE,
            end_date DATE,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Sync logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sync_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sync_id VARCHAR(255) UNIQUE,
            status VARCHAR(50),
            items_synced INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database tables initialized successfully!")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")

@app.get("/health")
def health():
    """Health check endpoint"""
    init_database()
    return {"status": "ok"}

# ============================================================================
# ENDPOINTS - AUTHENTICATION
# ============================================================================

@app.post("/auth/register", response_model=TokenResponse)
async def register(request: RegisterRequest, conn=Depends(get_db)):
    """
    Kullanıcı kaydı
    
    İstek:
    ```json
    {
        "email": "user@example.com",
        "password": "secure_password",
        "name": "John Doe",
        "age": 45,
        "country_code": "TR",
        "language": "tr",
        "diabetes_type": "type2",
        "has_hypertension": true
    }
    ```
    """
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Kullanıcı zaten var mı kontrol et
        cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Şifreyi hash'le
        password_hash = hash_password(request.password)
        
        # Kullanıcı oluştur
        cursor.execute("""
            INSERT INTO users (
                email, password_hash, name, age, country_code, 
                language, diabetes_type, has_hypertension
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, email, name
        """, (
            request.email,
            password_hash,
            request.name,
            request.age,
            request.country_code,
            request.language,
            request.diabetes_type,
            request.has_hypertension
        ))
        
        user = cursor.fetchone()
        conn.commit()
        
        # Token oluştur
        access_token = create_access_token(user["id"])
        
        return TokenResponse(
            access_token=access_token,
            user_id=user["id"],
            name=user["name"],
            email=user["email"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        cursor.close()

@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, conn=Depends(get_db)):
    """
    Kullanıcı girişi
    
    İstek:
    ```json
    {
        "email": "user@example.com",
        "password": "secure_password"
    }
    ```
    """
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Kullanıcı bul
        cursor.execute(
            "SELECT id, email, name, password_hash FROM users WHERE email = %s",
            (request.email,)
        )
        user = cursor.fetchone()
        
        if not user or not verify_password(request.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Token oluştur
        access_token = create_access_token(user["id"])
        
        # Son sync zamanını güncelle
        cursor.execute(
            "UPDATE users SET last_sync = %s WHERE id = %s",
            (datetime.utcnow(), user["id"])
        )
        conn.commit()
        
        return TokenResponse(
            access_token=access_token,
            user_id=user["id"],
            name=user["name"],
            email=user["email"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
    finally:
        cursor.close()

# ============================================================================
# ENDPOINTS - DATA SYNC (iOS ← → Web)
# ============================================================================

@app.post("/sync", response_model=SyncResponse)
async def sync_data(request: SyncRequest, conn=Depends(get_db)):
    """
    iOS'ten senkronizasyon
    
    İstek:
    ```json
    {
        "user_id": "uuid-here",
        "sync_id": "sync_12345",
        "measurements": [
            {
                "measurement_type": "glucose",
                "value": 105,
                "unit": "mg/dL",
                "measurement_date": "2026-06-11T09:30:00",
                "notes": "Before meal"
            }
        ],
        "moods": [
            {
                "emoji": "😊",
                "energy_level": 8,
                "stress_level": 3,
                "sleep_hours": 7.5,
                "notes": "Good day"
            }
        ],
        "timestamp": "2026-06-11T10:00:00"
    }
    ```
    
    Yanıt:
    ```json
    {
        "status": "success",
        "items_synced": 2,
        "message": "1 measurements and 1 moods synced"
    }
    ```
    """
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    items_synced = 0
    
    try:
        # Kullanıcı var mı kontrol et
        cursor.execute("SELECT id FROM users WHERE id = %s", (request.user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        
        # Sync log kaydı başlat
        cursor.execute("""
            INSERT INTO sync_logs (user_id, sync_id, status)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (request.user_id, request.sync_id, "pending"))
        
        sync_log_id = cursor.fetchone()["id"]
        
        # Ölçümleri kaydet
        if request.measurements:
            for measurement in request.measurements:
                cursor.execute("""
                    INSERT INTO measurements (
                        user_id, measurement_type, value, unit, 
                        measurement_date, notes
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    request.user_id,
                    measurement.measurement_type,
                    measurement.value,
                    measurement.unit,
                    measurement.measurement_date,
                    measurement.notes
                ))
                items_synced += 1
        
        # Ruh hallerini kaydet
        if request.moods:
            for mood in request.moods:
                # Her gün sadece 1 mood
                cursor.execute("""
                    INSERT INTO moods (
                        user_id, emoji, energy_level, stress_level,
                        sleep_hours, mood_date, notes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (user_id, mood_date) DO UPDATE
                    SET emoji = EXCLUDED.emoji,
                        energy_level = EXCLUDED.energy_level,
                        stress_level = EXCLUDED.stress_level,
                        sleep_hours = EXCLUDED.sleep_hours,
                        notes = EXCLUDED.notes
                """, (
                    request.user_id,
                    mood.emoji,
                    mood.energy_level,
                    mood.stress_level,
                    mood.sleep_hours,
                    datetime.now().date(),
                    mood.notes
                ))
                items_synced += 1
        
        # Sync log'u güncelle
        cursor.execute("""
            UPDATE sync_logs
            SET status = %s, items_synced = %s
            WHERE id = %s
        """, ("success", items_synced, sync_log_id))
        
        # Kullanıcı last_sync'i güncelle
        cursor.execute("""
            UPDATE users SET last_sync = %s WHERE id = %s
        """, (datetime.utcnow(), request.user_id))
        
        conn.commit()
        
        return SyncResponse(
            status="success",
            items_synced=items_synced,
            message=f"{len(request.measurements)} measurements and {len(request.moods)} moods synced"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        return SyncResponse(
            status="failed",
            items_synced=0,
            message=f"Sync failed: {str(e)}"
        )
    finally:
        cursor.close()

# ============================================================================
# ENDPOINTS - DATA RETRIEVAL (Web için)
# ============================================================================

@app.get("/api/measurements/{measurement_type}")
async def get_measurements(
    measurement_type: str,
    days: int = 30,
    token: str = None,
    conn=Depends(get_db)
):
    """
    Ölçümleri al (Glucose, BP, vb)
    
    Parametreler:
    - measurement_type: "glucose", "blood_pressure", "heart_rate"
    - days: Son kaç gün (default: 30)
    - token: JWT token
    
    Yanıt:
    ```json
    [
        {
            "id": "uuid",
            "value": 105,
            "unit": "mg/dL",
            "measurement_date": "2026-06-11T09:30:00",
            "notes": "Before meal"
        }
    ]
    ```
    """
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    
    user_id = verify_token(token)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT id, value, unit, measurement_date, notes
            FROM measurements
            WHERE user_id = %s 
              AND measurement_type = %s
              AND measurement_date > NOW() - INTERVAL '%s days'
            ORDER BY measurement_date DESC
        """, (user_id, measurement_type, days))
        
        measurements = cursor.fetchall()
        return measurements
        
    finally:
        cursor.close()

@app.get("/api/moods")
async def get_moods(days: int = 30, token: str = None, conn=Depends(get_db)):
    """Ruh hali verilerini al (Son 30 gün)"""
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    
    user_id = verify_token(token)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT emoji, energy_level, stress_level, sleep_hours, mood_date, notes
            FROM moods
            WHERE user_id = %s AND mood_date > CURRENT_DATE - INTERVAL '%s days'
            ORDER BY mood_date DESC
        """, (user_id, days))
        
        moods = cursor.fetchall()
        return moods
        
    finally:
        cursor.close()

# ============================================================================
# ROOT
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Diacora Health API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

