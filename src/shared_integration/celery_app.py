"""Celery application for production scan workers."""

from __future__ import annotations

import os

from celery import Celery


def create_celery_app() -> Celery:
    broker = os.getenv("INTEGRATION_BROKER_URL", "redis://127.0.0.1:6379/0")
    backend = os.getenv("INTEGRATION_RESULT_BACKEND", broker)
    application = Celery(
        "shared_integration",
        broker=broker,
        backend=backend,
        include=["shared_integration.tasks"],
    )
    application.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
        broker_connection_retry_on_startup=True,
        task_routes={
            "shared_integration.execute_job": {
                "queue": "analysis",
            }
        },
    )
    return application


celery_app = create_celery_app()

__all__ = ["celery_app", "create_celery_app"]
