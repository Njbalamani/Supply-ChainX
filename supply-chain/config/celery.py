"""Celery application for background supply-chain scans."""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("supplychainx")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.task_routes = {
    "vulnerability_scanner.tasks.run_scan": {"queue": "scans"},
    "projects.tasks.cleanup_archive": {"queue": "maintenance"},
}
