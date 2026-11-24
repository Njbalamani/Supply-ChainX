from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django import forms

from config.constants import Role
from .models import User


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)
    role = forms.ChoiceField(choices=[(Role.DEVELOPER.value, "Developer"), (Role.ANALYST.value, "Security Analyst")])

    class Meta:
        model = User
        fields = ("username", "email", "role", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        user.role = self.cleaned_data["role"]
        if commit:
            user.save()
        return user
