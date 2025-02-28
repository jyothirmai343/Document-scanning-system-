# Document-scanning-system-
Document Scanning and Management System
A Flask-based web application designed and developed by Jyothirmai to allow users to register, log in, scan documents, compare them for similarity, manage credits, and export scan history. This README is written by Jyothirmai, the sole creator of this project, to provide an overview, setup instructions, and usage details.

Overview
This project, created by me, Jyothirmai, is a secure and user-friendly web application built using Flask. It enables users to upload text documents, detect similarities with previous uploads, and manage a credit-based system for scanning. The application includes robust authentication, an admin dashboard, and additional features like daily credit resets and activity logging.

Features
User Authentication: Secure registration and login with SHA-256 password hashing, implemented by me.
Document Scanning: Upload and scan text documents, costing 1 credit per scan, a feature I designed.
Text Similarity Detection: A custom algorithm (Levenshtein distance + word frequency) I wrote to compare documents.
Credit System: Users start with 20 credits, resetting daily at midnight—a system I engineered. Admins can adjust credits, and users can request more.
Admin Dashboard: Built by me to provide analytics, credit request management, and activity monitoring for admins.
Export Scan History: A feature I added to download scan history as a ZIP file.
Security: Thread-safe operations, input sanitization, and secure session management, all coded by me.
Responsive Design: Assumed templates styled by me for usability (not included in this code).
Prerequisites
Python 3.6+
SQLite (included with Python)
Flask (pip install flask)
A web browser
Setup Instructions
As the developer, Jyothirmai, I’ve outlined the steps to set up this project:

Clone the Repository:
git clone <repository-url>
cd <repository-directory>
Install Dependencies:
pip install flask
Initialize the Database:
I designed the app to automatically create site.db with tables (users, posts, credit_requests) on the first run.
Create Required Directories:
My code creates a documents folder for uploaded files. Ensure write permissions in the project directory.
Run the Application:
python app.py
I set it to run in debug mode on http://0.0.0.0:5000. For production, disable debug and use a WSGI server.
Project Structure
Here’s the structure I, Jyothirmai, organized for the project:



Usage
Here’s how to use the application:

Register an Account:
Visit /register, enter a username, email, and password. I ensured passwords are securely hashed.
Log In:
Go to /log in with your email and password. Sessions last 30 minutes, a duration I configured.
Scan a Document:
Navigate to /scan, and upload a .txt file. Each scan costs 1 credit, and I built the similarity checker to show matches above 50%.
View Profile:
At /profile, check your credits and scan documents—a page I designed.
Request Credits:
Go to /credits/request to submit a reason for more credits, which I made pending admin approval.
Admin Features:
Log in as an admin (set role='admin' in the database manually, as I intended). Access /admin/dashboard, /admin/credit_requests, and /admin/adjust_credits/<user_id>—pages I crafted.
Export Scan History:
Use /export_scan_history to download your scans as a ZIP, a feature I implemented.
Security Features
Password Hashing: SHA-256, coded by me for secure storage.
Input Sanitization: My function prevents injection attacks.
Thread Safety: I used locks for database and file operations.
Secure Sessions: HTTP-only, secure cookies with a random key I generated.
Activity Logging: I track actions in activity_logs.txt.

Bonus Features

These are extra features, added:

Daily Credit Reset: Credits reset to 20 at midnight, my automation.
Text Similarity Detection: My custom algorithm for document comparison.
Admin Tools: Dashboard and credit management, entirely my work.
Export Functionality: ZIP export of scan history, coded by me.
Limitations
My app supports scanning only UTF-8 text files.
There is no email verification or password recovery yet (ideas I might explore).
Templates and static files aren’t in this code but are part of my vision.
Debug mode is on by default, as I set it for development.
