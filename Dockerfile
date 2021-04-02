FROM python:3.8-alpine

WORKDIR /karton/
RUN apk update
RUN apk add radare2
COPY karton/r2disasm r2disasm
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD [ "python", "-m", "r2disasm" ]