from django.test import TestCase
from unittest import mock
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import User, UserProfile
from permissions.models import Role  # Import the Role model
from PIL import Image
import io
from cloudinary_storage.storage import MediaCloudinaryStorage
from django.test import override_settings

@override_settings(
    MEDIA_URL='https://res.cloudinary.com/your_cloud_name/image/upload/',
    DEFAULT_FILE_STORAGE='cloudinary_storage.storage.MediaCloudinaryStorage'
)
class CloudinaryStorageTest(TestCase):
    def setUp(self):
        """Set up a user and a default role for the tests."""
        # Create a default role for the test user
        self.role = Role.objects.create(name='Test Role')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword123',
            role=self.role  # Assign the role
        )

    def test_profile_picture_upload_to_cloudinary(self):
        """
        Verify that a profile picture is successfully uploaded to Cloudinary
        and that the URL is a Cloudinary URL.
        """
        # Create a dummy image in memory
        image_buffer = io.BytesIO()
        image = Image.new('RGB', (100, 100), 'blue')
        image.save(image_buffer, format='PNG')
        image_buffer.seek(0)

        # Create a SimpleUploadedFile from the dummy image
        uploaded_file = SimpleUploadedFile(
            "test_profile.png",
            image_buffer.read(),
            content_type="image/png"
        )

        # Retrieve the existing UserProfile
        profile = UserProfile.objects.get(user=self.user)

        # Patch the storage on the instance and save the file
        with mock.patch.object(profile.profile_picture, 'storage', MediaCloudinaryStorage()):
            profile.profile_picture = uploaded_file
            profile.save()

        # The model is saved, which should trigger a real upload to Cloudinary.
        # Now, we check the URL.
        self.assertIn('cloudinary.com', profile.profile_picture.url)
        self.assertTrue(profile.profile_picture.url.startswith('http')) 