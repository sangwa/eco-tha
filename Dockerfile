FROM python:3.12-slim
WORKDIR /app
COPY cert_checker ./cert_checker
COPY cert-checker .
CMD ["/app/cert-checker"]
