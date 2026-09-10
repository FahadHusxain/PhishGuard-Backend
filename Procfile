release: python manage.py migrate --noinput
web: gunicorn --config gunicorn.conf.py backend.wsgi:application
