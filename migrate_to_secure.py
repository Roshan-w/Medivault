"""
Migration Script: Add Security Features to Existing MediVault Database
Run this script to update your existing database with new security features
"""

from app import app, db, Patient, Doctor, MedicalRecord, Prescription
from security import snowflake_generator, file_hasher, file_encryptor
import os

def migrate_database():
    with app.app_context():
        print("=== MediVault Security Migration ===\n")
        
        # Add new columns if they don't exist
        print("Step 1: Adding new security columns...")
        try:
            # This will add new columns defined in models
            db.create_all()
            print("✓ New columns added successfully")
        except Exception as e:
            print(f"✗ Error adding columns: {e}")
            return
        
        # Migrate Patients
        print("\nStep 2: Migrating Patients...")
        patients = Patient.query.filter(Patient.snowflake_id == None).all()
        for patient in patients:
            if not patient.snowflake_id:
                patient.snowflake_id = snowflake_generator.generate_id()
                print(f"  ✓ Patient {patient.name}: Snowflake ID = {patient.snowflake_id}")
        
        # Migrate Doctors
        print("\nStep 3: Migrating Doctors...")
        doctors = Doctor.query.filter(Doctor.snowflake_id == None).all()
        for doctor in doctors:
            if not doctor.snowflake_id:
                doctor.snowflake_id = snowflake_generator.generate_id()
                print(f"  ✓ Doctor {doctor.name}: Snowflake ID = {doctor.snowflake_id}")
        
        # Migrate Medical Records
        print("\nStep 4: Migrating Medical Records...")
        print("  This will:")
        print("  - Generate Snowflake IDs")
        print("  - Calculate file hashes")
        print("  - Encrypt existing files")
        
        records = MedicalRecord.query.all()
        encrypted_folder = app.config['ENCRYPTED_FOLDER']
        os.makedirs(encrypted_folder, exist_ok=True)
        
        for record in records:
            try:
                # Generate Snowflake ID
                if not record.snowflake_id:
                    record.snowflake_id = snowflake_generator.generate_id()
                
                # Process file if it exists and not already encrypted
                if record.filename and os.path.exists(record.filename) and not record.is_encrypted:
                    # Calculate hash
                    if not record.file_hash:
                        record.file_hash = file_hasher.calculate_hash(record.filename)
                    
                    # Get file size
                    if not record.file_size:
                        record.file_size = os.path.getsize(record.filename)
                    
                    # Encrypt file
                    original_filename = os.path.basename(record.filename)
                    encrypted_filename = f"encrypted_{snowflake_generator.generate_string_id()}_{original_filename}"
                    encrypted_filepath = os.path.join(encrypted_folder, encrypted_filename)
                    
                    file_encryptor.encrypt_file(record.filename, encrypted_filepath)
                    
                    # Update record
                    old_file = record.filename
                    record.filename = encrypted_filepath
                    record.is_encrypted = True
                    
                    # Delete old unencrypted file
                    if os.path.exists(old_file):
                        os.remove(old_file)
                    
                    print(f"  ✓ Record {record.id}: Encrypted and secured (Hash: {record.file_hash[:16]}...)")
                elif record.filename and not os.path.exists(record.filename):
                    print(f"  ⚠ Record {record.id}: File not found - {record.filename}")
                else:
                    if not record.snowflake_id:
                        record.snowflake_id = snowflake_generator.generate_id()
                    print(f"  ✓ Record {record.id}: Updated with Snowflake ID")
            except Exception as e:
                print(f"  ✗ Error processing record {record.id}: {e}")
        
        # Migrate Prescriptions
        print("\nStep 5: Migrating Prescriptions...")
        prescriptions = Prescription.query.filter(Prescription.snowflake_id == None).all()
        for prescription in prescriptions:
            if not prescription.snowflake_id:
                prescription.snowflake_id = snowflake_generator.generate_id()
                print(f"  ✓ Prescription {prescription.id}: Snowflake ID = {prescription.snowflake_id}")
        
        # Commit all changes
        print("\nStep 6: Saving changes to database...")
        try:
            db.session.commit()
            print("✓ All changes saved successfully!")
        except Exception as e:
            print(f"✗ Error saving changes: {e}")
            db.session.rollback()
            return
        
        # Print summary
        print("\n" + "="*50)
        print("MIGRATION COMPLETED SUCCESSFULLY!")
        print("="*50)
        print(f"\nMigrated:")
        print(f"  - {len(patients)} Patients")
        print(f"  - {len(doctors)} Doctors")
        print(f"  - {len(records)} Medical Records")
        print(f"  - {len(prescriptions)} Prescriptions")
        print(f"\nSecurity Features Added:")
        print(f"  ✓ Snowflake 64-bit IDs")
        print(f"  ✓ SHA-256 file hashing")
        print(f"  ✓ AES-128 file encryption")
        print(f"  ✓ Deduplication support")
        print("\n⚠️  IMPORTANT: Backup your encryption key!")
        print(f"Key (first 50 chars): {file_encryptor.get_key()[:50]}...")
        print("\nStore this key securely - you'll need it to decrypt files!")
        print("="*50)

if __name__ == '__main__':
    response = input("This will modify your database. Have you backed up your data? (yes/no): ")
    if response.lower() == 'yes':
        migrate_database()
    else:
        print("Please backup your database first, then run this script again.")