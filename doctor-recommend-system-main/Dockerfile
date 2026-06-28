FROM python:3.10-slim

ENV PYTHONUNBUFFERED 1

RUN apt-get update -y && \
    apt-get install -y binutils libproj-dev gdal-bin

WORKDIR /backend-api

COPY requirements.txt /backend-api/
RUN python -m pip install --upgrade pip
RUN python -m pip install -r requirements.txt

COPY . /backend-api/

# Spacy models
RUN python -m pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.4.1/en_core_web_md-3.4.1-py3-none-any.whl
RUN python -m pip install https://s3-us-west-2.amazonaws.com/ai2-s2-scispacy/releases/v0.5.1/en_core_sci_md-0.5.1.tar.gz

CMD python manage.py migrate && python seed_medical_data.py && python seed_data.py && gunicorn HospitalManagement.wsgi:application --bind 0.0.0.0:${PORT:-8000}
