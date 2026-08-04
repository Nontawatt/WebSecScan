# WebSecScan — ETDA ขมธอ.4-2559 + NCSA 2568
# อิมเมจเดียวจบ: Python + fpdf2 + ฟอนต์ไทย + เครื่องมือสแกนจริง (nmap/sqlmap/wapiti)
FROM python:3.12-slim

# เครื่องมือสแกน + ฟอนต์ไทย (Garuda อยู่ใน fonts-thai-tlwg)
# หมายเหตุ: nikto ไม่มีใน Debian trixie แล้ว — เครื่องมือตัวนี้ข้ามได้ (ระบบ degrade เอง)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        fonts-thai-tlwg \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ไลบรารี Python: fpdf2 (PDF ไทย) + wapiti3 (สแกน DAST)
RUN pip install --no-cache-dir fpdf2 wapiti3

WORKDIR /app
COPY *.py /app/
COPY fonts/ /app/fonts/

# bind 0.0.0.0 เพื่อให้ map port ออกมาที่ host ได้; เก็บผลไว้ที่ /app/data (mount volume)
ENV ETDA_HOST=0.0.0.0 \
    ETDA_PORT=8091 \
    PYTHONUNBUFFERED=1
EXPOSE 8091
VOLUME ["/app/data"]

CMD ["python", "app.py"]
