FROM python:3.12-alpine
COPY server.py /srv/server.py
EXPOSE 80 8080 5432 6379 2375
CMD ["python3", "-u", "/srv/server.py"]
