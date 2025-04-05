# Dotnet Security

Dotnet Security is a secure web application built with ASP.NET Core. It demonstrates secure coding practices, including role-based access control, password hashing, SQL injection prevention, and protection against cross-site scripting (XSS) vulnerabilities.

## Features

- **User Authentication**: Secure login and registration with hashed passwords using BCrypt.
- **Role-Based Access Control**: Restrict access to specific routes and features based on user roles (e.g., admin, user).
- **SQL Injection Prevention**: All database queries use parameterized statements to prevent SQL injection attacks.
- **Cross-Site Scripting (XSS) Protection**: User inputs are sanitized and encoded to prevent XSS vulnerabilities.
- **Session Management**: User roles and session data are securely managed using ASP.NET Core's session middleware.

## Technologies Used

- **Backend**: ASP.NET Core MVC
- **Database**: MySQL
- **Authentication**: BCrypt for password hashing
- **Frontend**: Razor Views with Bootstrap for styling
