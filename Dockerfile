FROM python

RUN apt-get update && apt-get install -y xmlsec1

ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

ADD app /app/
WORKDIR /app

CMD /app/app.py