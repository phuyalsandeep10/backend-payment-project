import uuid
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from authentication.models import User
from organization.models import Organization
from team.models import Team
from permissions.models import Role, Permission

class TeamEndpointTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        # Setup Organizations
        cls.organization1 = Organization.objects.create(name="Org 1")
        cls.organization2 = Organization.objects.create(name="Org 2")

        # Setup Roles
        cls.role1 = Role.objects.create(name='Admin', organization=cls.organization1)
        
        # Setup Permissions
        cls.can_create_team, _ = Permission.objects.get_or_create(codename='create_team', name='Can create team', category='Team')
        cls.can_edit_team, _ = Permission.objects.get_or_create(codename='edit_team', name='Can edit team', category='Team')
        cls.can_delete_team, _ = Permission.objects.get_or_create(codename='delete_team', name='Can delete team', category='Team')
        cls.can_view_all_teams, _ = Permission.objects.get_or_create(codename='view_all_teams', name='Can view all teams', category='Team')
        
        cls.role1.permissions.add(
            cls.can_create_team,
            cls.can_edit_team,
            cls.can_delete_team,
            cls.can_view_all_teams,
        )

        cls.role2 = Role.objects.create(name='Member', organization=cls.organization1)
        cls.role3 = Role.objects.create(name='Other Org Member', organization=cls.organization2)

        # Setup Users
        cls.user1 = User.objects.create_user(username='user1', email='user1@example.com', password='password123', organization=cls.organization1, role=cls.role1)
        cls.user2 = User.objects.create_user(username='user2', email='user2@example.com', password='password123', organization=cls.organization1, role=cls.role2)
        cls.user3 = User.objects.create_user(username='user3', email='user3@example.com', password='password123', organization=cls.organization2, role=cls.role3)
        cls.unassigned_user = User.objects.create_user(username='unassigned', email='unassigned@example.com', password='password123', organization=cls.organization1, role=cls.role2)

        # Setup Teams
        cls.team1 = Team.objects.create(name="Team 1", organization=cls.organization1, created_by=cls.user1)
        cls.team1.members.add(cls.user1, cls.user2)

        cls.team2 = Team.objects.create(name="Team 2", organization=cls.organization2, created_by=cls.user3)
        cls.team2.members.add(cls.user3)

    def setUp(self):
        # Authenticate User 1
        self.client.force_authenticate(user=self.user1)

        # URLS
        self.list_create_url = reverse('team-list')
        self.detail_url = reverse('team-detail', kwargs={'pk': self.team1.pk})
        self.other_org_detail_url = reverse('team-detail', kwargs={'pk': self.team2.pk})

    def test_list_teams_in_own_organization(self):
        """
        A user should only see teams within their own organization.
        """
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only see team1
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.team1.name)

    def test_create_team(self):
        """
        A user can create a team within their organization.
        """
        data = {
            "name": "New Team",
            "organization": self.organization1.id,
            "members": [self.user1.id, self.user2.id]
        }
        response = self.client.post(self.list_create_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Team.objects.filter(name="New Team", organization=self.organization1).exists())

    def test_retrieve_team_in_own_organization(self):
        """
        A user can retrieve details of a team in their own organization.
        """
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.team1.name)

    def test_cannot_retrieve_team_from_another_organization(self):
        """
        A user cannot retrieve details of a team from another organization.
        """
        response = self.client.get(self.other_org_detail_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_team(self):
        """
        A user can update a team's details.
        """
        update_data = {"name": "Team 1 Updated"}
        response = self.client.patch(self.detail_url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.team1.refresh_from_db()
        self.assertEqual(self.team1.name, "Team 1 Updated")

    def test_add_members_to_team(self):
        """
        A user can add members to a team.
        """
        update_data = {"members": [self.user1.id, self.user2.id, self.unassigned_user.id]}
        response = self.client.patch(self.detail_url, update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.team1.refresh_from_db()
        self.assertEqual(self.team1.members.count(), 3)
        self.assertIn(self.unassigned_user, self.team1.members.all())

    def test_remove_members_from_team(self):
        """
        A user can remove members from a team.
        """
        update_data = {"members": [self.user1.id]}
        response = self.client.patch(self.detail_url, update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.team1.refresh_from_db()
        self.assertEqual(self.team1.members.count(), 1)
        self.assertNotIn(self.user2, self.team1.members.all())
        
    def test_delete_team(self):
        """
        A user can delete a team they created.
        """
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Team.objects.filter(pk=self.team1.pk).exists()) 