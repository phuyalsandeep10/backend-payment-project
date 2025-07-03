import csv
from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from clients.models import Client
from organization.models import Organization
from authentication.models import User

class Command(BaseCommand):
    help = 'Adds clients to a specific organization from a CSV file, assigning them to a specific user.'

    def add_arguments(self, parser):
        parser.add_argument('organization_id', type=int, help='The ID of the organization to add clients to.')
        parser.add_argument('user_id', type=int, help='The ID of the user (salesperson) who is creating these clients.')
        parser.add_argument('--csv', type=str, required=True, help='The path to the CSV file containing client data.')

    def handle(self, *args, **options):
        organization_id = options['organization_id']
        user_id = options['user_id']
        csv_file_path = options['csv']

        try:
            organization = Organization.objects.get(pk=organization_id)
            self.stdout.write(self.style.SUCCESS(f"Found organization: '{organization.name}'"))
        except Organization.DoesNotExist:
            raise CommandError(f"Organization with ID '{organization_id}' does not exist.")

        try:
            creator = User.objects.get(pk=user_id, organization=organization)
            self.stdout.write(self.style.NOTICE(f"Assigning new clients to user: '{creator.email}'"))
        except User.DoesNotExist:
            raise CommandError(f"User with ID '{user_id}' not found in organization '{organization.name}'.")

        try:
            with open(csv_file_path, mode='r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                clients_added = 0
                clients_skipped = 0

                for row in reader:
                    client_name = row.get('client_name')
                    email = row.get('email')
                    phone_number = row.get('phone_number')

                    if not all([client_name, email, phone_number]):
                        self.stdout.write(self.style.WARNING(f"Skipping row due to missing data: {row}"))
                        clients_skipped += 1
                        continue
                    
                    try:
                        client, created = Client.objects.get_or_create(
                            email=email,
                            organization=organization,
                            defaults={
                                'client_name': client_name,
                                'phone_number': phone_number,
                                'created_by': creator,
                            }
                        )

                        if created:
                            client.full_clean()
                            client.save()
                            self.stdout.write(self.style.SUCCESS(f"Successfully added client: '{client_name}' ({email})"))
                            clients_added += 1
                        else:
                            self.stdout.write(self.style.NOTICE(f"Client with email '{email}' already exists for this organization. Skipping."))
                            clients_skipped += 1

                    except ValidationError as e:
                        self.stdout.write(self.style.WARNING(f"Skipping client '{client_name}' due to a validation error: {e}"))
                        clients_skipped += 1
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"An unexpected error occurred for client '{client_name}': {e}"))
                        clients_skipped += 1


        except FileNotFoundError:
            raise CommandError(f"CSV file not found at path: '{csv_file_path}'")
        
        self.stdout.write("--------------------")
        self.stdout.write(self.style.SUCCESS(f"Script finished."))
        self.stdout.write(f"Clients added: {clients_added}")
        self.stdout.write(f"Clients skipped: {clients_skipped}") 