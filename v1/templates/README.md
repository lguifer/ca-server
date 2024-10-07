# FAQ: Certificate Authority (CA) Tool

## 1. What is this tool used for?
This tool allows users to generate a Certificate Authority (CA) and manage certificates. It supports actions such as signing certificates, listing certificates, and revoking certificates.

## 2. What technologies are used in this project?
- **HTML5** for structure.
- **CSS (Bootstrap 4.5)** for styling and layout.
- **JavaScript** for handling form validation and sanitization.
- **Python Flask** for the server-side logic and dynamic content rendering.

## 3. How does the tool sanitize user input?
The tool uses a JavaScript function called `sanitizeInput()` to strip out any potentially dangerous characters from user inputs. The input is treated as text content, which prevents script injection attacks. Additionally, a regular expression is used to allow only alphanumeric characters, underscores, periods, hyphens, and backslashes.

## 4. What are the available actions in the tool?
- **Sign Certificate**: Sign a certificate with the generated CA.
- **List Certificates**: View a list of existing certificates.
- **Revoke Certificate**: Revoke an existing certificate.

## 5. How does the form validation work?
Form validation ensures that required fields are filled out and that the inputs match the specified format:
- The `sanitizeForm()` function is used to validate each field before form submission.
- A regular expression (`/^[a-zA-Z0-9_.\-\\]*$/`) ensures that the input contains only valid characters.
- If any field is invalid, the form will not submit, and an error border will appear around the invalid fields.

## 6. What happens when I submit the form?
When you submit the form, the JavaScript code checks which button was pressed:
- If the "Manage Certificates" button is pressed, the form is validated and sanitized before submitting.
- If the "Generate CA" button is pressed, a confirmation dialog is displayed asking if you're sure you want to generate a CA.

## 7. How are error messages displayed?
If any input field is invalid, it will be highlighted with a red border, and the form will prevent submission until the errors are corrected.

## 8. How does the form dynamically show or hide fields?
The tool hides and shows specific fields based on the selected action from the "Select Action" dropdown. When you choose an action (e.g., "Sign Certificate"), the appropriate fields (like "Common Name") will appear, while unrelated fields are hidden.

## 9. How can I customize the list of certificates available for revocation?
The list of certificates in the "Cert Path" dropdown is dynamically populated using a Flask template. You can modify the certificate list by adjusting the data sent from the backend to the template.

## 10. Can I prevent form submission with the Enter key?
Yes, the tool includes functionality to prevent form submission when the Enter key is pressed to avoid accidental submissions.
