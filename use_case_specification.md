# Use Case Specification: Security Console

| Field | Description |
|---|---|
| Name | Security Console |
| Purpose | The detection of SQL injection attacks. |
| Context | The application is triggered when users try to access financial data. |
| Prerequisites | The console is running and the Random Forest model has been loaded. |
| Narrative | 1. Any user who can reach the console can submit queries. The console has no authentication, so administrator actions (reviewing the quarantine vault and running the stress benchmark) are not restricted to an admin role.<br>2. The system detects whether a SQL injection attack is present after a query is input.<br>3. The query is stored and then translated to determine whether it is a SQL injection attack.<br>4. Malicious queries are isolated in a forensic quarantine vault and structured into compliance vault schemas for forensic analysis.<br>5. The system evaluates its detection capability by passing structured transactions through the machine learning model. |
| Alternatively | Any other user with access to the console can also submit queries. |
| Outcome | SQL injection attacks are detected and prevented. |
| Exceptions | The application does not detect SQL injection attacks and is judged invalid. |

## Known gaps

- **Access control:** the console has no authentication. Administrator actions can currently be performed by any user with access.
- **Unseen attacks:** detection has only been evaluated on templated queries from the same generator used for training (see the README Limitations section).