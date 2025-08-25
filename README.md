
# Hostel Grevience Management System

A web-based platform for students to register and report hostel-related problems, with authentication and issue tracking.


## Overview

Under this project, the hostel residents can report to their hostel authorities easily on any problem they are facing like lack of maintenance, electricity defects, water or internet problems with the residence. It facilitates the procedure by enabling students to file complaints through the internet which can be traced and monitored by the administrators.
## Problem Statement

In many hostels, students still rely on manual reporting (paper or verbal) for maintenance issues, which often leads to delays, loss of records, or lack of accountability. This project solves the problem by digitizing the reporting process and enabling transparent communication.
## Tech Stack


**Frontend**: HTML, CSS, JavaScript, EJS

**Backend**: Node.js, Express.js

**Database**: PostgreSQL

**Authentication**: bcrypt (password hashing), email verification (Nodemailer with Google App Password)

## Run Locally

Clone the project

```bash
  git clone https://github.com/AbhiramGupta/Hostel_grevience_management_system.git
```

Go to the project directory

```bash
  cd Hostel Grevience Management System
```

Setup Environment Variables

* DB_USER=<your_postgres_username>
* DB_PASSWORD=<your_postgres_password>
* DB_HOST=localhost
* DB_PORT=5432
* DB_DATABASE=<your_database_name>

* NODE_ENV=development

* EMAIL_USER=<your_email_address>
* APP_PASSWORD=<your_app_password>

* BASE_URL=http://localhost:3000

Install Dependencies

```bash
  npm install
```

Start the server

```bash
  node server.js
```



## Results and Conclusions

* Students can register, log in, and securely report problems.

* Issues are stored in a database for better tracking and resolution.

* Email verification ensures valid accounts.

* The system improves accountability and reduces delays in resolving hostel problems.
## Future Work

**Real-time Issue Tracking**: Students and administrators are able to see the real time status of the registered complaints until when they are resolved.

**Department-wise messages**: Everything will automatically direct towards respective department (e.g., plumbing, electricity, carpentry) and the respective workers assigned to the department will get instant notifications.

**Student and Admin Notifications**: Student gets notified when their complaint is accepted and solved and the same happens to the admins as they will also get notifications on new grievanes raised.


**Mobile/PWA Support**: A mobile friendly version or Progressive Web App to cause complaint registration and monitoring to be easier.
## Author and Contact

**Abhiram Sriramwar**

**Email**: abhiramgupta42@gmail.com

**Github**: https://github.com/AbhiramGupta