from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from .models import CustomUser,LoginSession
# Register your models here.

# ----------------------
# 1. Form for creating users (with password confirmation)
# ----------------------
class CustomUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ("email", "full_name", "phone_number")

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match.")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])  # hashes password
        if commit:
            user.save()
        return user

# ----------------------
# 2. Form for updating existing users
# ----------------------
class CustomUserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField(
        label=("Password"),
        help_text=(
            "Raw passwords are not stored, so you cannot see the user's password, "
            "but you can change it using <a href=\"../password/\">this form</a>."
        ),
    )

    class Meta:
        model = CustomUser
        fields = ("email", "full_name", "phone_number", "password", "is_active", "is_staff", "is_superuser")

    def clean_password(self):
        return self.initial["password"]  # Keeps existing hashed password unchanged

# ----------------------
# 3. Custom admin panel for CustomUser
# ----------------------
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm            # used in admin when adding a user
    form = CustomUserChangeForm                  # used when editing a user
    model = CustomUser

    list_display = ("email", "full_name", "phone_number", "is_staff", "is_active")  # columns shown in user list
    list_filter = ("is_staff", "is_active", "is_superuser")  # filters in sidebar

    search_fields = ("email", "full_name", "phone_number")   # enables search
    ordering = ("email",)                                    # default sorting

    # Fields shown when viewing/editing a user
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (("Personal info"), {"fields": ("full_name", "phone_number", "address", "city", "state", "zip_code", "country")}),
        (("Permissions"), {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    # Fields shown when adding a new user in admin
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),  # styling class for admin UI
                "fields": ("email", "full_name", "phone_number", "password1", "password2", "is_staff", "is_active"),
            },
        ),
    )
    
class LoginSessionAdmin(admin.ModelAdmin):
    list_display = ['user','location','ip_address','login_time']    
admin.site.register(LoginSession,LoginSessionAdmin)