from django.apps import AppConfig


class SbomGeneratorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sbom_generator"
    verbose_name = "SBOM Generator"
