
# Welcome to Purple Teaming with Detection-as-Code for Modern SIEM

This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.

## Lab 1 - Writing Our First Detection

Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection.

### Terms we'll reference

- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

Sample Okta Event - Failed Login:
  
``` json
{
 "actor": {
  "alternateId": "lemmy@heavymetals.io",
  "displayName": "Lemmy Kilmister",
  "id": "0u7gkf3fd41J4kku5d7",
  "type": "User"
 },
 "client": {
  "ipAddress": "111.111.111.111"
 },
 "eventType": "user.session.start",
 "outcome": {
  "reason": "INVALID_CREDENTIALS",
  "result": "FAILURE"
 },
 "p_event_time": "2023-01-23 09:59:53.650807",
 "p_log_type": "Okta.SystemLog",
 "p_parse_time": "2023-01:23 10:02:33.650807"
}
```
