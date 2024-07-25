from scanner_api.views import flush_online, fleshWeb, daily,licence_check
from django.http import HttpRequest


def flush_online_task():
    request = HttpRequest()
    flush_online(request)


def flesh_web():
    request = HttpRequest()
    fleshWeb(request)


def dailyReport():
    request = HttpRequest()
    daily(request)


def active_check():
    request = HttpRequest()
    licence_check(request)

