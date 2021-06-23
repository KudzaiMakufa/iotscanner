# pull official base image

FROM ubuntu:18.04
FROM python:3.8




# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN apt update && \
                apt install -yqq \
                build-essential \
                musl-dev \
                nmap \
                python3-netifaces \
                python3-opencv
RUN pip3 install --upgrade pip setuptools wheel
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

# copy project
COPY . .


