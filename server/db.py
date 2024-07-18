from dotenv import load_dotenv
from pathlib import Path
import os

load_dotenv()

DEBUG = bool(int(os.environ.get('DJANGO_DEBUG')))
BASE_DIR = Path(__file__).resolve().parent.parent

if DEBUG:
    
    dataBases = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

else:
    dataBases = {
            'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('POSTGRES_DB'),
            'USER': os.environ.get('POSTGRES_USER'),
            'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
            'HOST': os.environ.get('POSTGRES_HOST'),
            'PORT': os.environ.get('POSTGRES_PORT')
        }
    }