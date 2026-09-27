"""
Django settings for soc_project project.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Path configuration to access the platform src configurations
sys.path.append(str(BASE_DIR))

from src.config import settings

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = settings.get("JWT_SECRET_KEY", "django-insecure-*&$=z_^x0lntz!2wdy=sf+--va!)#qgk350(wxd-20c+mlca(d")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = settings.get("ENVIRONMENT", "development") != "production"

ALLOWED_HOSTS = ["*"]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Core third-party apps
    'rest_framework',
    'corsheaders',
    
    # Local application
    'soc_app',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware', # Put CORS at the very top
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'soc_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'soc_project.wsgi.application'

# Database Connection Parsing Configuration
# Translates SQLalchemy database URL schemes into Django ORM database parameters
db_url = settings.DATABASE_URL
DATABASES = {}

if db_url.startswith("sqlite"):
    db_path = db_url.replace("sqlite:///", "")
    # Handle absolute/relative file paths
    if not os.path.isabs(db_path):
        db_path = os.path.join(BASE_DIR, db_path)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': db_path,
    }
elif db_url.startswith("postgresql"):
    # Parse: postgresql://username:password@host:port/db_name
    cleaned = db_url.replace("postgresql://", "")
    auth, rest = cleaned.split("@", 1)
    username, password = auth.split(":", 1)
    conn, db_name = rest.split("/", 1)
    host, port = conn.split(":", 1) if ":" in conn else (conn, "5432")
    
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': db_name,
        'USER': username,
        'PASSWORD': password,
        'HOST': host,
        'PORT': port,
    }
else:
    # Fallback to default relative SQLite DB
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'database' / 'db_sqlite.db',
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS Configurations
CORS_ALLOW_ALL_ORIGINS = True

# Django REST Framework & SimpleJWT Authentication configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'ALGORITHM': settings.JWT_ALGORITHM,
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
}
