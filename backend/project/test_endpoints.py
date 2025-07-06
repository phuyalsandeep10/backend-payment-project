from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from faker import Faker
import uuid

from organization.models import Organization
from authentication.models import User
from permissions.models import Role
from team.models import Team
from .models import Project

fake = Faker()

class ProjectEndpointTests(APITestCase):
    def setUp(self):
        # Set up Organizations, Roles, and Users
        self.org1 = Organization.objects.create(name="Org 1")
        self.role1 = Role.objects.create(name="Manager", organization=self.org1)
        self.user1 = User.objects.create_user(
            email="user1@org1.com", password="password", organization=self.org1, role=self.role1
        )

        self.org2 = Organization.objects.create(name="Org 2")
        self.role2 = Role.objects.create(name="Member", organization=self.org2)
        self.user2 = User.objects.create_user(
            email="user2@org2.com", password="password", organization=self.org2, role=self.role2
        )

        # Set up Teams
        self.team1 = Team.objects.create(name="Team 1", organization=self.org1)
        self.team1.members.add(self.user1)

        self.team2 = Team.objects.create(name="Team 2", organization=self.org2)
        self.team2.members.add(self.user2)

        # Set up Projects
        self.project1 = Project.objects.create(
            name="Project 1",
            created_by=self.user1,
            description="Description for project 1",
            start_date="2024-01-01",
            end_date="2024-12-31",
        )
        self.project1.teams.add(self.team1)

        self.project2 = Project.objects.create(
            name="Project 2",
            created_by=self.user2,
            description="Description for project 2"
        )
        self.project2.teams.add(self.team2)
        
        self.client.force_authenticate(user=self.user1)
        
        self.list_create_url = reverse('project-list')
        self.detail_url = reverse('project-detail', kwargs={'pk': self.project1.pk})

    def test_list_projects_for_user_team(self):
        """User should only see projects associated with their teams."""
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.project1.name)

    def test_create_project(self):
        """User can create a project, which is associated with their team."""
        data = {
            "name": "New Project",
            "description": "A new project created via API.",
            "start_date": "2025-01-01",
            "end_date": "2025-12-31",
            "teams": [self.team1.id]
        }
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Project.objects.filter(name="New Project").exists())

    def test_retrieve_own_project(self):
        """User can retrieve a project they are a member of."""
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.project1.name)

    def test_cannot_retrieve_other_org_project(self):
        """User cannot retrieve a project from another organization."""
        other_org_url = reverse('project-detail', kwargs={'pk': self.project2.pk})
        response = self.client.get(other_org_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_project(self):
        """User can update a project they are a member of."""
        update_data = {"name": "Project 1 Updated"}
        response = self.client.patch(self.detail_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project1.refresh_from_db()
        self.assertEqual(self.project1.name, "Project 1 Updated")

    def test_delete_project(self):
        """User can delete a project they created."""
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Project.objects.filter(pk=self.project1.pk).exists())

    def test_non_creator_cannot_delete_project(self):
        """A user who did not create the project cannot delete it."""
        # Log in as user2, who is not the creator of project1
        non_creator_user = User.objects.create_user(
            email='noncreator@org1.com', password='password', organization=self.org1, role=self.role1
        )
        self.team1.members.add(non_creator_user)
        self.client.force_authenticate(user=non_creator_user)
        
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) 