### What is basically a vulnerability in web development ?

A vulnerability in web development refers to a weakness or flaw in a web application that can be exploited by an attacker to gain unauthorized access, compromise data, or disrupt services. These vulnerabilities can arise from various sources, including poor coding practices, misconfigurations, and lack of proper security measures.

#### One example of well-known vulnerabilities aka SQL Injection

SQL Injection is a common and serious vulnerability in web development based on relational databases. It occurs when an attacker is able to insert or "inject" malicious SQL code into a query. This can happen if user input is not properly sanitized or validated before being used in SQL queries.


<br>

##### How it works ?

* First the user input: An attacker enters malicious SQL code into a form field, such as a login form.
* Next the SQL query: The web application constructs an SQL query using the user input.
* Then an holy grail execution: The malicious SQL code is executed by the database, potentially allowing the attacker to access, modify, or delete data.

<br>

### The OWASP (Open Web Application Security Project) Top Ten 

The OWASP (Open Web Application Security Project) Top Ten is a regularly updated list of the most critical web application security risks.
Here are the top ten OWASP vulnerabilities from the latest update:

<br>

| **Vuln** | **Title**                                         | **Description**                                                                                     |
| ---- | --------------------------------------------- | ----------------------------------------------------------------------------------------------- |  
|  **A01** | Broken Access Control                         | Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits. | 
|  **A02** | Cryptographic failures                        | Many older or weak cryptographic algorithms are present in systems today, many as the result of legacy code that can be exploited both in transit and at rest. |
|  **A03** | Injection                                     | The application is vulnerable to attacks due to the injection of invalid data. Injection flaws, such as SQL, NoSQL, OS command injection, etc., occur when untrusted data is sent to an interpreter as part of a command or query. |
|  **A04** | Insecure design                               | A lack of security controls or a failure to implement security controls properly can be a risk. This is a broad category that includes risks due to missing or ineffective security controls. |
|  **A05** | Security Misconfiguration                     | The most commonly seen issue. This is typically a result of using default settings, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, error messages containing sensitive information, and more. |
|  **A06** | Vulnerable and Outdate Components             | Vulnerable and outdated components, including software and dependencies, introduce security risks. |
|  **A07** | Identification and Authentification failures  | Authentication mechanisms can be exploited to assume other users’ identities temporarily or permanently. |
|  **A08** | Software and data integrity failure           | Software and data integrity are not assured at any point during its lifecycle. |
|  **A09** | Security loggingand monitoring failures       | This is a broader category focusing on the failure to detect, escalate, and respond to active breaches. |
|  **A10** | Server-side request forgery (SSRF)            | An SSRF attack happens when a web application is tricked into making requests to an unintended location. |

<br>

### The Common Weakness Enumeration (CWE)

The Common Weakness Enumeration (CWE) is a community-developed list that categorizes software weaknesses, helping developers, security professionals, and organizations understand and mitigate risks.

The CWE Top 25 represents the most dangerous software weaknesses that are widely exploited by attackers. These vulnerabilities are ranked based on their exploitability, prevalence, and impact. Understanding these CWEs is crucial for securing software applications, as they often lead to serious threats like data breaches, denial-of-service attacks, remote code execution, and system compromise. This list is compiled from real-world vulnerability databases (e.g., NVD, CVSS scores, and CVE reports) and provides insight into the most critical security issues in modern applications.

<br>

| **Rank** | **CWE ID** | **Weakness Name** | **Description** |
|---------|-----------|-------------------|----------------|
| 1 | **CWE-787** | Out-of-bounds Write | Writing data past the end or before the beginning of a buffer, leading to crashes or code execution. |
| 2 | **CWE-79** | Cross-Site Scripting (XSS) | Injection of malicious scripts into web pages viewed by users, enabling data theft or session hijacking. |
| 3 | **CWE-89** | SQL Injection | Injecting malicious SQL queries to manipulate databases, extract data, or execute commands. |
| 4 | **CWE-416** | Use After Free | Accessing memory after it has been freed, causing crashes or arbitrary code execution. |
| 5 | **CWE-20** | Improper Input Validation | Failing to properly validate user input, leading to injection attacks, crashes, or logic flaws. |
| 6 | **CWE-125** | Out-of-bounds Read | Reading data outside the allocated buffer, potentially leaking sensitive information. |
| 7 | **CWE-22** | Path Traversal | Manipulating file paths to access restricted directories or files outside the intended scope. |
| 8 | **CWE-352** | Cross-Site Request Forgery (CSRF) | Tricking users into executing unwanted actions on a web application where they are authenticated. |
| 9 | **CWE-78** | OS Command Injection | Injecting malicious system commands via user input, leading to unauthorized command execution. |
| 10 | **CWE-287** | Improper Authentication | Weak or missing authentication mechanisms allowing unauthorized access. |
| 11 | **CWE-476** | NULL Pointer Dereference | Dereferencing a NULL pointer, causing crashes or denial-of-service conditions. |
| 12 | **CWE-190** | Integer Overflow or Wraparound | Performing arithmetic operations that exceed integer limits, leading to unexpected behavior or security flaws. |
| 13 | **CWE-502** | Deserialization of Untrusted Data | Deserializing untrusted data, allowing attackers to execute arbitrary code or escalate privileges. |
| 14 | **CWE-269** | Improper Privilege Management | Assigning incorrect permissions, allowing unauthorized users to access sensitive resources. |
| 15 | **CWE-863** | Improper Authorization | Failing to enforce proper authorization checks, leading to unauthorized data access. |
| 16 | **CWE-306** | Missing Authentication for Critical Function | Allowing access to sensitive actions without proper authentication checks. |
| 17 | **CWE-732** | Incorrect Permission Assignment for Critical Resource | Assigning overly permissive file or resource permissions, enabling unauthorized modifications. |
| 18 | **CWE-798** | Use of Hard-coded Credentials | Storing credentials in source code, making them easily exploitable if leaked. |
| 19 | **CWE-362** | Race Condition | Improper handling of concurrent execution, leading to unpredictable behavior or data corruption. |
| 20 | **CWE-400** | Uncontrolled Resource Consumption (DoS) | Allowing excessive resource usage, leading to service slowdowns or denial-of-service attacks. |
| 21 | **CWE-601** | Open Redirect | Redirecting users to untrusted sites, often used for phishing or social engineering attacks. |
| 22 | **CWE-276** | Incorrect Default Permissions | Assigning insecure default permissions to resources, increasing the attack surface. |
| 23 | **CWE-918** | Server-Side Request Forgery (SSRF) | Exploiting server-side web requests to access internal systems or sensitive data. |
| 24 | **CWE-611** | XML External Entity (XXE) Injection | Processing untrusted XML input, allowing attackers to read local files or execute system commands. |
| 25 | **CWE-94** | Code Injection | Injecting arbitrary code into an application, leading to remote execution or privilege escalation. |


<br>

### SUDO MODE: ANALYSIS OF THE WEB APP

For detecting vulnerabilities in the given app it is possible to first start reading and understanding the code. But when the number of files containing multiples lines of code, this process can be overwhelming.

So to take a better approach I try to use a standard SAST. But wait what is a SAST ?

A **SAST (Static Application Security Testing)** is a method of analyzing source code, bytecode, or binary code for security vulnerabilities without executing the application. SAST tools examine the code for patterns that indicate potential security flaws, such as SQL injection, cross-site scripting (XSS), buffer overflows, and more.

It is aimed to:

* identify vulnerabilities early in the development lifecycle, often during the coding phase.
* analyze the codebase to find security issues, including syntax errors, logic errors, and other potential vulnerabilities.
* be integrated into the development pipeline to automatically scan code for vulnerabilities
* analyze a wide range of code, including different programming languages and frameworks


For my work, I choose to use Semgrep OSS.

<br>

### A look into Semgrep OSS

Semgrep OSS (Open Source Software) is a powerful, open-source static analysis tool designed to find bugs and security vulnerabilities in code. It is developed by r2c, a company focused on improving software security through innovative tools.

<br>

#### How it works

Semgrep uses a pattern-matching engine to find specific code patterns that are known to be problematic. This allows it to identify a wide range of security issues and code smells.

Also, developers can write custom rules to detect specific issues in their codebase. This makes Semgrep highly flexible and adaptable to different coding standards and security requirements.

Like others SAST, it can be integrated into various development workflows, including CI/CD pipelines, IDEs, and code review tools and this ensures that security scans are performed consistently and automatically.

Of course, Semgrep is designed to be fast, making it suitable for large codebases and frequent scans.

Finally, it has a free license for personal use and benefits from a vibrant community that contributes to its development and provides support.

<br>

#### Guide for installation

First it is recommanded to create a virtual Python environment as Semgrep is based on that programming language.

```python
# m stand for module
python3 -m venv env
```

The next step is to ensure pip is upgraded

```python
python3 -m pip install --upgrade pip
```

After that installing Semgrep via pip

```python
pip install semgrep
```

As I'm working on the free license of Semgrep and also the CLI (Command Line Interface), I have one unique task

```python
semgrep scan --config auto web-app-vulnerability-analysis-project-
```

<br>

#### The output explained - Vulnerabilities exposed

After scanning for the vulnerabilities, you can get all the detected vulnerabilities here: 

[Vulnerabilities report from Semgrep output](vuln_sem_report.txt)

<br>

#### CWE, OWASP guidelines related to these vulnerabilities detected

<br>

The vulnerabilities detected can be classified following the OWASP Top Ten and CWE guidelines as:

<br>

| Vulnerability                                      | OWASP Top Ten                                                                 | CWE                                       |
|------------------------------------------------------|-------------------------------------------------------------------------------|-------------------------------------------|
| Missing CSRF Middleware                             | A03:2021 – Injection, A07:2021 – Identification and Authentication Failures | CWE-352: Cross-Site Request Forgery (CSRF)|
| Using Default Session Cookie Name                   | A02:2021 – Cryptographic Failures, A09:2021 – Security Logging and Monitoring Failures | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor, CWE-522: Insufficiently Protected Credentials |
| 'domain' Parameter Not Set for Session Cookie        | A02:2021 – Cryptographic Failures, A03:2021 – Injection                      | CWE-614: Sensitive Cookie Without 'HttpOnly' Flag, CWE-311: Missing Encryption of Sensitive Data |
| 'expires' Parameter Not Set for Session Cookie       | A02:2021 – Cryptographic Failures, A03:2021 – Injection                      | CWE-614: Sensitive Cookie Without 'HttpOnly' Flag, CWE-311: Missing Encryption of Sensitive Data |
| 'httpOnly' Parameter Not Set for Session Cookie      | A03:2021 – Injection, A07:2021 – Identification and Authentication Failures   | CWE-614: Sensitive Cookie Without 'HttpOnly' Flag, CWE-311: Missing Encryption of Sensitive Data |
| 'path' Parameter Not Set for Session Cookie          | A02:2021 – Cryptographic Failures, A03:2021 – Injection                      | CWE-614: Sensitive Cookie Without 'HttpOnly' Flag, CWE-311: Missing Encryption of Sensitive Data |
| 'secure' Parameter Not Set for Session Cookie        | A02:2021 – Cryptographic Failures, A03:2021 – Injection                      | CWE-614: Sensitive Cookie Without 'HttpOnly' Flag, CWE-311: Missing Encryption of Sensitive Data |
| Hardcoded Session Secret                             | A02:2021 – Cryptographic Failures, A09:2021 – Security Logging and Monitoring Failures | CWE-798: Use of Hard-coded Credentials, CWE-259: Use of Hard-coded Password |


<br>

##### Explanation and solutions

Tracking the vulnerabilities leads to these discovers:

<br>

**1. A missing CSRF middleware**

A CSRF (Cross-Site Request Forgery) middleware was not detected in the Express application. A CSRF attack is an attack where a malicious user tricks an authenticated user into executing unwanted actions on a web application. Without CSRF protection, your application is vulnerable to such attacks, which can lead to unauthorized actions being performed on behalf of authenticated users.

**Solution**
* Install a CSRF middleware
```bash
npm install csurf
```
* Next, configuring the middleware in the app
```javascript
const csurf = require('csurf');
const csrfProtection = csurf({ cookie: true });

const app = express();
app.use(csrfProtection);
```
* Finally we have to make sure to include the CSRF token in the form and validate it in the routes


<br>

**2. Using Default Session Cookie Name**

The usage of default session cookie name can make your application more susceptible to attacks. The default cookie name can be used to fingerprint the server, making it easier for attackers to target specific vulnerabilities associated with the identified framework or library. This can lead to more effective and targeted attacks against your application.

**Solution**
* Change the default session cookie name to a custom name:
```javascript
app.use(session({
  name: 'myCustomSessionName',
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true
}));
```

<br>

**3. The 'domain' parameter is not set for session cookie**

The 'domain' parameter specifies the domain to which the cookie will be sent. If this parameter is not set, the cookie may be sent to unauthorized domains, potentially exposing sensitive information or allowing unauthorized access. This can lead to security risks, including session hijacking and other cookie-based attacks.

**Solution**
* Set the 'domain' parameter to your specific domain:

```javascript
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    domain: 'yourdomain.com'
  }
}));
```

<br>

**4. The 'expires' parameter is not set for session Cookie**

The 'expires' parameter defines the expiration date for the cookie. If this parameter is not set, the cookie may persist indefinitely, which can pose security risks. Persistent cookies can be exploited by attackers to maintain unauthorized access to user sessions, leading to potential data breaches and other security issues.

**Solution**
* Set the 'expires' parameter to a specific date or duration:

```javascript
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    expires: new Date(Date.now() + 3600000) // 1 hour
  }
}));
```

<br>

**5. The 'httpOnly' parameter is not set for session cookie**

The 'httpOnly' flag ensures that the cookie is not accessible via JavaScript, which helps protect against cross-site scripting (XSS) attacks. Without this flag, an attacker could use JavaScript to steal the session cookie, leading to session hijacking and other security issues.

**Solution**
* Set the 'httpOnly' parameter to true:

```javascript
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true
  }
}));
```
<br>

**6. The 'path' parameter is not set for session cookie**

The 'path' parameter specifies the URL path that must exist in the requested URL for the browser to send the cookie. If this parameter is not set, the cookie may be sent to unauthorized paths, potentially exposing sensitive information or allowing unauthorized access. This can lead to security risks, including session hijacking and other cookie-based attacks.

**Solution**
* Set the 'path' parameter to a specific path:

```javascript
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    path: '/'
  }
}));
```

<br>

**7. 'secure' Parameter Not Set for Session Cookie**

The 'secure' flag ensures that the cookie is only sent over HTTPS connections, which helps protect against man-in-the-middle attacks. Without this flag, the cookie may be sent over insecure HTTP connections, potentially exposing sensitive information to attackers.

**Solution**
* Set the 'secure' parameter to true:

```javascript
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true
  }
}));

```

<br>

**8. Hardcoded Session Secret**

A hardcoded session secret was detected in the Express application. Hardcoding secrets in the source code can lead to secret leakage, which can be exploited by malicious actors. If the secrets are exposed, attackers can use them to gain unauthorized access to your application, leading to potential data breaches and other security issues.

**Solution**
* Use environment variables to store secrets:

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    httpOnly: true,
    expires: new Date(Date.now() + 3600000), // 1 hour
    path: '/',
    domain: 'yourdomain.com'
  }
}));
```
* Store environment variables in a .env file:
```text
SESSION_SECRET=your_secure_secret_key
```

* And use a package like dotenv to load environment variables:
```bash
npm install dotenv
```

```javascript
require('dotenv').config();
```

By implementing these solutions, I can significantly enhance the security of the application, protecting it against common vulnerabilities and ensuring a more secure environment for the users.
