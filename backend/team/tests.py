from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from authentication.models import User
from organization.models import Organization
from permissions.models import Role
from .models import Team

class TeamAPITests(APITestCase):

    def setUp(self):
        # Orgs
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')

        # Super Admin
        self.super_admin_role = Role.objects.create(name='Super Admin')
        self.super_admin = User.objects.create_user(
            email='superadmin@test.com',
            username='superadmin',
            password='password123',
            role=self.super_admin_role,
            is_superuser=True
        )

        # Org 1 Admin and User
        self.org1_admin_role = Role.objects.create(name='Org Admin', organization=self.org1)
        self.org1_admin = User.objects.create_user(
            email='admin1@test.com',
            username='admin1',
            password='password123',
            organization=self.org1,
            role=self.org1_admin_role
        )
        self.org1_user = User.objects.create_user(email='user1@test.com', username='user1', password='password123', organization=self.org1)

        # Org 2 Admin
        self.org2_admin_role = Role.objects.create(name='Org Admin', organization=self.org2)
        self.org2_admin = User.objects.create_user(
            email='admin2@test.com',
            username='admin2',
            password='password123',
            organization=self.org2,
            role=self.org2_admin_role
        )

        # Teams
        self.team1_org1 = Team.objects.create(name='Team Alpha', organization=self.org1)
        self.team2_org2 = Team.objects.create(name='Team Bravo', organization=self.org2)

        self.team_list_url = reverse('team-list')
        self.team_detail_url = reverse('team-detail', kwargs={'pk': self.team1_org1.pk})

    def test_org_admin_can_list_own_teams(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.get(self.team_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.team1_org1.name)

    def test_org_admin_cannot_list_other_org_teams(self):
        self.client.force_authenticate(user=self.org2_admin)
        response = self.client.get(self.team_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only see their own team (Team Bravo)
        team_names = [team['name'] for team in response.data]
        self.assertIn(self.team2_org2.name, team_names)
        self.assertNotIn(self.team1_org1.name, team_names)
        
    def test_super_admin_can_list_all_teams(self):
        self.client.force_authenticate(user=self.super_admin)
        response = self.client.get(self.team_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), Team.objects.count())

    def test_regular_user_cannot_list_teams(self):
        self.client.force_authenticate(user=self.org1_user)
        response = self.client.get(self.team_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_org_admin_can_create_team(self):
        self.client.force_authenticate(user=self.org1_admin)
        data = {'name': 'Team Gamma', 'members': [self.org1_user.id]}
        response = self.client.post(self.team_list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(Team.objects.filter(name='Team Gamma', organization=self.org1).exists())
        new_team = Team.objects.get(name='Team Gamma')
        self.assertIn(self.org1_user, new_team.members.all())

    def test_org_admin_can_update_team(self):
        self.client.force_authenticate(user=self.org1_admin)
        # Add user to team
        self.team1_org1.members.add(self.org1_user)
        data = {'name': 'Team Alpha Updated', 'members': []} # Remove user
        response = self.client.put(self.team_detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.team1_org1.refresh_from_db()
        self.assertEqual(self.team1_org1.name, 'Team Alpha Updated')
        self.assertEqual(self.team1_org1.members.count(), 0)

    def test_org_admin_can_delete_team(self):
        self.client.force_authenticate(user=self.org1_admin)
        response = self.client.delete(self.team_detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Team.objects.filter(pk=self.team1_org1.pk).exists())

    def test_org_admin_cannot_access_other_org_team(self):
        self.client.force_authenticate(user=self.org1_admin)
        other_org_url = reverse('team-detail', kwargs={'pk': self.team2_org2.pk})
        response = self.client.get(other_org_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
