import csv
import os
from django.core.management.base import BaseCommand
from api.models import WhitelistDomain

class Command(BaseCommand):
    help = 'Loads Top 1 Million domains from CSV into Database'

    def handle(self, *args, **kwargs):
        # File ka naam (Jo tumne backend folder mein rakhi hai)
        file_path = 'top1m.csv'  
        
        # Check karo file hai ya nahi
        if not os.path.exists(file_path):
            self.stdout.write(self.style.ERROR(f'❌ Error: {file_path} file backend folder mein nahi mili!'))
            return

        print("⏳ Reading CSV file... (Ye thoda time lega)")
        
        domains_to_create = []
        count = 0

        # Optional: Agar purana data saaf karna ho to niche wali line uncomment kardo
        # WhitelistDomain.objects.all().delete() 

        with open(file_path, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                try:
                    # Tranco CSV format: "1,google.com"
                    # row[0] rank hota hai, row[1] domain hota hai
                    domain = row[1]
                    
                    # Batch list mein daalo
                    domains_to_create.append(WhitelistDomain(domain=domain))
                    count += 1

                    # Har 50,000 records par save karo (Taake RAM full na ho)
                    if len(domains_to_create) >= 50000:
                        WhitelistDomain.objects.bulk_create(domains_to_create, ignore_conflicts=True)
                        print(f"✅ Loaded {count} domains...")
                        domains_to_create = [] # List khali karo
                except:
                    continue

        # Jo bache hue domains hain unhe bhi save karo
        if domains_to_create:
            WhitelistDomain.objects.bulk_create(domains_to_create, ignore_conflicts=True)

        self.stdout.write(self.style.SUCCESS(f'🎉 SUCCESSFULLY LOADED {count} DOMAINS!'))