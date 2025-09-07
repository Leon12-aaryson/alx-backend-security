from django.core.management.base import BaseCommand
from ip_tracking.tasks import detect_anomalies


class Command(BaseCommand):
    help = 'Run anomaly detection task manually'

    def add_arguments(self, parser):
        parser.add_argument(
            '--async',
            action='store_true',
            help='Run the task asynchronously using Celery',
        )

    def handle(self, *args, **options):
        if options['async']:
            # Run asynchronously using Celery
            result = detect_anomalies.delay()
            self.stdout.write(
                self.style.SUCCESS(f'Anomaly detection task queued with ID: {result.id}')
            )
        else:
            # Run synchronously
            try:
                result = detect_anomalies()
                self.stdout.write(
                    self.style.SUCCESS(f'Anomaly detection completed: {result}')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error running anomaly detection: {str(e)}')
                )
