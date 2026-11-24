from django.views.generic import TemplateView


class DocsHomeView(TemplateView):
    template_name = "docs/index.html"


class ArchitectureView(TemplateView):
    template_name = "docs/architecture.html"


class ERDiagramView(TemplateView):
    template_name = "docs/er_diagram.html"


class APIDocsView(TemplateView):
    template_name = "docs/api.html"
