from __future__ import annotations

from celery import shared_task


@shared_task(name="projects.tasks.cleanup_archive")
def cleanup_archive(archive_id: int) -> str:
    from .models import ProjectArchive

    archive = ProjectArchive.objects.filter(pk=archive_id).first()
    if not archive:
        return "missing"
    archive.file.delete(save=False)
    archive.delete()
    return "deleted"
