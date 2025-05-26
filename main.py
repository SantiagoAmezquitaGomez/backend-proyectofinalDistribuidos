from fastapi import FastAPI, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional
import spacy
from pymongo import MongoClient
import os
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Configuración JWT
SECRET_KEY = os.getenv("SECRET_KEY", "secret_key_super_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

from fastapi import HTTPException, status

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar el token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# Configuración de MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://santy:santy1@clustersa.a1wdk.mongodb.net/")
client = MongoClient(MONGO_URI)
db = client["resumenes_db"]
usuarios_col = db["usuarios"]

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    user = usuarios_col.find_one({"username": username})
    if user:
        return user
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Configuración de MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://santy:santy1@clustersa.a1wdk.mongodb.net/")
client = MongoClient(MONGO_URI)
db = client["resumenes_db"]
coleccion = db["resumenes"]

# Cargar el modelo de spaCy en español
try:
    nlp = spacy.load("es_core_news_sm")
except:
    nlp = None

@app.get("/")
def read_root():
    return {"mensaje": "¡Bienvenido al backend del generador de resúmenes!"}

@app.post("/upload")
def upload_pdf(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """
    Recibe un archivo PDF, extrae el texto y devuelve un resumen.
    """
    import io
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        return JSONResponse(status_code=500, content={"error": "PyPDF2 no está instalado. Ejecuta: pip install PyPDF2"})
    try:
        contents = file.file.read()
        pdf_stream = io.BytesIO(contents)
        reader = PdfReader(pdf_stream)
        texto = ""
        for page in reader.pages:
            texto += page.extract_text() or ""
        if not texto.strip():
            return JSONResponse(status_code=400, content={"error": "No se pudo extraer texto del PDF."})
        # Procesar el texto extraído con spaCy si el modelo está cargado
        if not nlp:
            return JSONResponse(status_code=500, content={"error": "Modelo spaCy no cargado. Ejecuta: python -m spacy download es_core_news_sm"})
        doc = nlp(texto)
        keywords = set([token.lemma_ for token in doc if token.pos_ in ["NOUN", "VERB"] and not token.is_stop])
        sentences = list(doc.sents)
        resumen = []
        for sent in sentences:
            if any(word in sent.text for word in keywords):
                resumen.append(sent.text)
            if len(resumen) >= 3:
                break
        resumen_texto = " ".join(resumen) if resumen else sentences[0].text if sentences else ""
        # Guardar en MongoDB
        doc_db = {
            "tipo": "pdf",
            "texto_original": texto,
            "resumen": resumen_texto,
            "metadatos": {"nombre_archivo": file.filename},
            "usuario": current_user["username"]
        }
        coleccion.insert_one(doc_db)
        return {"resumen": resumen_texto, "texto_extraido": texto[:5000]}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Error procesando el PDF: {str(e)}"})

@app.post("/summarize")
def summarize_text(text: str = Form(...), current_user: dict = Depends(get_current_user)):
    """
    Recibe texto plano y devuelve un resumen usando spaCy.
    """
    if not nlp:
        return JSONResponse(status_code=500, content={"error": "Modelo spaCy no cargado. Ejecuta: python -m spacy download es_core_news_sm"})
    doc = nlp(text)
    # Extraer frases clave (sustantivos y verbos lematizados)
    keywords = set([token.lemma_ for token in doc if token.pos_ in ["NOUN", "VERB"] and not token.is_stop])
    # Algoritmo extractivo simple: seleccionar frases que contengan palabras clave
    sentences = list(doc.sents)
    resumen = []
    for sent in sentences:
        if any(word in sent.text for word in keywords):
            resumen.append(sent.text)
        if len(resumen) >= 3:
            break
    resumen_texto = " ".join(resumen) if resumen else sentences[0].text if sentences else ""
    # Guardar en MongoDB
    doc_db = {
        "tipo": "texto",
        "texto_original": text,
        "resumen": resumen_texto,
        "metadatos": {},
        "usuario": current_user["username"]
    }
    coleccion.insert_one(doc_db)
    return {"resumen": resumen_texto}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Credenciales incorrectas"})
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

from fastapi import HTTPException, status
from jose import JWTError

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar el token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/history/{user_id}")
def get_history(user_id: str, current_user: dict = Depends(get_current_user)):
    """
    Devuelve el historial de resúmenes de un usuario (requiere autenticación JWT).
    """
    # Consulta filtrando por usuario si se implementa autenticación real
    historial = list(coleccion.find({"usuario": user_id}, {"_id": 0}))
    return {"historial": historial}

@app.post("/register")
def register_user(data: dict):
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Usuario y contraseña requeridos")
    if usuarios_col.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    hashed_password = pwd_context.hash(password)
    usuarios_col.insert_one({
        "username": username,
        "full_name": username,
        "hashed_password": hashed_password,
        "disabled": False
    })
    return {"mensaje": "Usuario registrado exitosamente"}