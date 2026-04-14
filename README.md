# Medivault

## Project Purpose
Medivault is a secure Flask application designed for patient-doctor consent management and the encrypted storage of medical records. The primary aim of Medivault is to ensure that sensitive patient data is managed securely while providing a seamless interface for both patients and physicians.

## Features
- **Consent Management:** Manage and track patient consent for sharing medical records with various healthcare providers.
- **Encrypted Storage:** Safeguard sensitive medical records through encryption, ensuring unauthorized access is prevented.
- **User Authentication:** Robust user authentication mechanisms that ensure that only authorized personnel have access to sensitive data.
- **Comprehensive Dashboard:** An interactive dashboard for users to view and manage their consent and records.
- **Reporting Tools:** Generate reports based on the consent provided and data access.

## Tech Stack
- **Backend:** Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** SQLite (for development) / PostgreSQL (for production)
- **Authentication:** Flask-Login, JWT
- **Encryption:** Flask-Security

## Architecture
Medivault follows a standard MVVM architecture, separating the application logic from the user interface. The architecture includes:
- **Model:** Manages the data and business logic.
- **View:** The user interface and presentation layer built with HTML and JavaScript.
- **ViewModel:** Handles the interaction between the Model and View, typically through Flask routes.

## Setup Instructions
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Roshan-w/Medivault.git
   cd Medivault
   ```

2. **Create a Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Environment Variables:**
   - Create a `.env` file and set necessary variables like `SECRET_KEY`, `DATABASE_URL`. 

5. **Database Setup:**
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. **Run the Application:**
   ```bash
   flask run
   ```

## Usage Guidelines
- **Accessing the Application:** Open your web browser and navigate to `http://localhost:5000` to access the Medivault application.
- **Register/Login:** Users must register and log in to utilize the features of Medivault. Upon logging in, users can manage consents and view medical records according to their access rights.
- **Consent Management:** Navigate to the consent management interface to give or revoke consent for data sharing with physicians.

## Conclusion
Medivault aims to streamline and secure the management of medical records through thoughtful design and implementation. Regular updates and user feedback will continue to enhance the features and functionality of Medivault.