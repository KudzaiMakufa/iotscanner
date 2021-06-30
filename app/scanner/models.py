from django.db import models
from django.utils import timezone
from datetime import datetime


# Create your models here.


class Scanner(models.Model):
 

    vendor = models.CharField(default=None ,max_length=100)
    ipaddress = models.CharField(default=None ,max_length=100)
    macaddress = models.CharField(default=None ,max_length=100)
    vulners = models.CharField(default=None ,max_length=100)
    os_name = models.CharField(default=None ,max_length=100)