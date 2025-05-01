from cryptography.fernet import Fernet
import hashlib
import base64
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import getpass

# =========================
# Setup Database
# =========================

Base = declarative_base()


class PasswordEntry(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True)
    service = Column(String, unique=True, nullable=False)
    encrypted_password = Column(String, nullable=False)


engine = create_engine('sqlite:///passwords.db')
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()


def get_master_key(master_password):
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)

class PasswordManager:
    def __init__(self, master_password):
        self.key = get_master_key(master_password)
        self.fernet = Fernet(self.key)

    def add_password(self, service, password):
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        existing_entry = session.query(PasswordEntry).filter_by(service=service).first()

        if existing_entry:
            print(f"Updating existing password for {service}.")
            existing_entry.encrypted_password = encrypted_password
        else:
            entry = PasswordEntry(service=service, encrypted_password=encrypted_password)
            session.add(entry)

        session.commit()
        print(f"Password for {service} saved.")

    def get_password(self, service):
        """Retrieve and decrypt a password for a service."""
        entry = session.query(PasswordEntry).filter_by(service=service).first()
        if not entry:
            print(f"No password found for {service}.")
            return
        try:
            decrypted_password = self.fernet.decrypt(entry.encrypted_password.encode()).decode()
            print(f"Password for {service}: {decrypted_password}")
        except Exception:
            print("Failed to decrypt password. Is your master password correct?")

    def list_services(self):
        """List all services with stored passwords."""
        entries = session.query(PasswordEntry).all()
        if not entries:
            print("No passwords stored.")
        else:
            print("Stored services:")
            for entry in entries:
                print(f"- {entry.service}")


def main():
    master_password = getpass.getpass("Enter your master password: ")
    manager = PasswordManager(master_password)

    while True:
        print("\nChoose an action:")
        print("1. Add a new password")
        print("2. Get a password")
        print("3. List all services")
        print("4. Quit")
        choice = input("Choice: ")

        if choice == '1':
            service = input("Service name: ")
            password = getpass.getpass("Password: ")
            manager.add_password(service, password)
        elif choice == '2':
            service = input("Service name: ")
            manager.get_password(service)
        elif choice == '3':
            manager.list_services()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
