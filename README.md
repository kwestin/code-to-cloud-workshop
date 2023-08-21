
# Code-to-Cloud: Securing the Software Supply Chain Workshop

This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.



## Lab 1 - Writing Our First Detection 

Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection.

### Terms we'll reference

- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)


In this exercise, we will create our first detection using Python in Panther using GitHub as our data source. We will start by creating a low-priority alert if a new invite to our GitHub organization is sent. You can find a sample log event under "Investigate -> Query Builder" or use this sample event for your unit test. 

``` json
{
	"_document_id": "wDBpTX1LrspfiwTEv1LKjw",
	"action": "org.invite_member",
	"actor": "lemmy-heavymetals",
	"actor_id": "142338540",
	"actor_location": {
		"country_code": "US"
	},
	"at_sign_timestamp": "2023-08-17 22:06:14.96",
	"business": "heavy-metals",
	"business_id": "66164",
	"created_at": "2023-08-17 22:06:14.96",
	"operation_type": "create",
	"org": "heavymetalsio",
	"org_id": 141669676,
	"p_any_actor_ids": [
		"142338540",
		"142546341"
	],
	"p_any_usernames": [
		"dio-heavymetals",
		"lemmy-heavymetals"
	],
	"p_event_time": "2023-08-17 22:06:14.96",
	"p_log_type": "GitHub.Audit",
	"p_parse_time": "2023-08-17 22:17:35.475",
	"p_row_id": "76ebfa5fb2e5c5a8b3b5bf831a01",
	"p_schema_version": 0,
	"p_source_id": "6a05d4a5-e080-4211-8f5c-b23f7c0f9437",
	"p_source_label": "Heavy MEtals",
	"p_timeline": "2023-08-17 22:06:14.96",
	"user": "dio-heavymetals",
	"user_id": "142546341"
}

```

1. In the Panther Console, navigate to Build > Detections > Create New
2. Select "Rule"
3. Under "Basic Info" enter a name in the "Name" field your new detection starting with your name. Example: "[YOUR NAME]'s New GitHub Invite"
4. Click "Next"
5. Under "Log Types" type in "Okta" and select "Okta.SystemLog"
6. Under "Set Alert Field" set the "Severity" to "Low"
7. Next scroll down to "Unit Test" and click "Add New" copy and past the above sample JSON or from the "Investigation -> Query Builder" and past.
8. Write a detection with the ```rule()``` function (hint: look for the "action" and "operation_type" elements in the JSON)
9. Next let's add more context to the alert using the ```title()``` function so that it says "A new invite was sent to [user] by [actor] for org [org name]

<details>
<summary> View Answer </summary>
	
``` python
def rule(event):
    return event.get("action") == "org.invite_member" and event.get("operation_type") == "create" 

def title(event):
    return (
        f"A new invite was sent to [{event.get('user', '<UNKNOWN_USER>')}] by "
        f"by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        f" for org [{event.get('org', '<UNKNOWN_ORG>')}]"
    )
    
 ```

</details>

## Lab - 2 Expanding Detections for Multiple Events with Unit Tests

Looking at the GitHub logs in "Investigate -> Query Builder" we notice that the JSON evnets for  ***Invite Member***, ***Add Member***, and ***Update Member*** all follow the same format. Let's add the two additional JSON events as unit tests and see if we can write one detection to ***Rule them all!***. We will also use the ```severity()``` function to increase the severity of the alert depending on the action taken. 

 1. Go back to the detection you have made and change the title to "[YOUR NAME]'s GitHub New User Activity" to make it more generic.
 2. Name the ***Unit Test*** you just created for the "org.invite_member" and rename the tab "Invite"
 3. Create two new ***Unit Test*** tabs for "Add Member" and another for "Modify Member"
 4. Either go to "Investigation -> Query Builder" and find the GitHub events for "org.add_member" and "org.update_member" and or copy and past the samples here:

#### Add Member JSON Event
``` json
{
	"_document_id": "S8M5F0HvalWi_7wMb8j6dA",
	"action": "org.add_member",
	"actor": "lemmy-heavymetals",
	"actor_id": "142338540",
	"at_sign_timestamp": "2023-08-17 22:07:16.263",
	"business": "heavy-metals",
	"business_id": "66164",
	"created_at": "2023-08-17 22:07:16.263",
	"operation_type": "create",
	"org": "heavymetalsio",
	"org_id": 141669676,
	"p_any_actor_ids": [
		"142338540",
		"142546341"
	],
	"p_any_usernames": [
		"dio-heavymetals",
		"lemmy-heavymetals"
	],
	"p_event_time": "2023-08-17 22:07:16.263",
	"p_log_type": "GitHub.Audit",
	"p_parse_time": "2023-08-17 22:18:35.235",
	"p_row_id": "5e9f2dc3eb9f90e28fd7bc831a07",
	"p_schema_version": 0,
	"p_source_id": "6a05d4a5-e080-4211-8f5c-b23f7c0f9437",
	"p_source_label": "Heavy MEtals",
	"p_timeline": "2023-08-17 22:07:16.263",
	"user": "dio-heavymetals",
	"user_id": "142546341"
}

```
#### Modify Member JSON Event

``` json
{
	"_document_id": "24WJD3hWZWfLn5HKKqRW_w",
	"action": "org.update_member",
	"actor": "lemmy-heavymetals",
	"actor_id": "142338540",
	"actor_location": {
		"country_code": "US"
	},
	"at_sign_timestamp": "2023-08-17 22:19:49.374",
	"business": "heavy-metals",
	"business_id": "66164",
	"created_at": "2023-08-17 22:19:49.374",
	"operation_type": "modify",
	"org": "heavymetalsio",
	"org_id": 141669676,
	"p_any_actor_ids": [
		"142338540",
		"142546341"
	],
	"p_any_usernames": [
		"dio-heavymetals",
		"lemmy-heavymetals"
	],
	"p_event_time": "2023-08-17 22:19:49.374",
	"p_log_type": "GitHub.Audit",
	"p_parse_time": "2023-08-17 22:31:35.156",
	"p_row_id": "5e9f2dc3eb9f90e28fd7bc831a0f",
	"p_schema_version": 0,
	"p_source_id": "6a05d4a5-e080-4211-8f5c-b23f7c0f9437",
	"p_source_label": "Heavy MEtals",
	"p_timeline": "2023-08-17 22:19:49.374",
	"user": "dio-heavymetals",
	"user_id": "142546341"
}

```
5. Modify the detection so that if the ```action``` value is ```org.invite_member```, ```org.add_member```, or ```org.update_member``` the alert will trigger
7. Modify the ```title()``` function so that it returns a value that makes sense based on the value of the ```action``` parameter.
8. Add the ```severity()``` function so it returns a different severity depending on the value of the ```action``` parameter (```invite_member``` = LOW, ```add_member``` = MEDIUM and ```update_member``` = HIGH)
9. To run all unit tests press the ***Run All*** button, you should see a list of tests with increasing severities.
10. Let's also add a negative test, copy one of the JSON samples and create a new unit test tab with the name 'Null' and replace the ```action``` value in the JSON for the unit test as just "null"

![Unit Tests](/img/unit_tests_L1E2.png)  

<details>
<summary> View Example Answer  </summary>
	
``` python
def rule(event):
    return event.get("action") == "org.invite_member" or event.get("action") == "org.add_member" or event.get("action") == "org.update_member"
    

def severity(event):
    if event.get("action") == "org.invite_member":
        return "LOW"
    if  event.get("action") == "org.add_member":
        return "MEDIUM"
    if event.get("action") == "org.update_member":
        return "HIGH"
    else: 
        return "INFO"

def title(event):
    return (
        f"A [{event.get('action', '<UNKNOWN_ACTION>')}] action was created [{event.get('user', '<UNKNOWN_USER>')}] "
        f"by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        f" for org [{event.get('org', '<UNKNOWN_ORG>')}]"
    )
 
 ```

</details>


## Lab 3 -  Protected Branch Destroy and Repo Visibility


### Lab 3 Exercise 1

Now we will leverage the power of Panther's Security Data Lake to dig into potentially malicious activity and write a detection from scratch. 

1. We will start with our Security Data Lake; please navigate in the Panther console to "Investigate -> Query Builder" and let's search for recent events that occurred in GitHub
2. One key set of security controls that GitHub provides is the ability to protect branches; this defines roles and whether collaborators can delete/modify/branches as well as requirements for pushes to the branch. If branch protection is deleted, it opens the code up for potential issues.
3. Find the log event where branch protection was destroyed and use that event as a unit test for writing a new detection.
4. Use the ```title()``` function to provide additional context in the alert title, including the repository and actor. 

<details>
<summary> Hint 1: </summary>
Look for the action "protected_branch.destroy"
</details>


<details>
<summary> Hint 2: </summary>
Both the "actor" and "repo" elements will provide the context.
</details>





<!--
Sample GitHub Event - Branch Protection Destroy:
  
``` json
{
	"_document_id": "TW0bUcX1kShMfQcgbVHJoA",
	"action": "protected_branch.destroy",
	"actor": "lemmy-heavymetals",
	"actor_id": "1696440",
	"actor_location": {
		"country_code": "US"
	},
	"admin_enforced": false,
	"at_sign_timestamp": "2023-08-15 20:31:05.594",
	"business": "heavy-metals",
	"business_id": "66164",
	"created_at": "2023-08-15 20:31:05.594",
	"linear_history_requirement_enforcement_level": 0,
	"name": "master",
	"operation_type": "remove",
	"org": "heavymetalsio",
	"org_id": 141669676,
	"p_any_actor_ids": [
		"1696440"
	],
	"p_any_usernames": [
		"lemmy-heavymetals"
	],
	"p_event_time": "2023-08-15 20:31:05.594",
	"p_log_type": "GitHub.Audit",
	"p_parse_time": "2023-08-15 20:42:35.246",
	"p_row_id": "ca0b768ff4a5fcec85f2aefe1908",
	"p_schema_version": 0,
	"p_source_id": "6a05d4a5-e080-4211-8f5c-b23f7c0f9437",
	"p_source_label": "Heavy MEtals",
	"p_timeline": "2023-08-15 20:31:05.594",
	"public_repo": false,
	"pull_request_reviews_enforcement_level": 0,
	"repo": "heavymetalsio/metal-trader",
	"repo_id": 678958857,
	"required_status_checks_enforcement_level": 0
}

```

-->

``` python
def rule(event):
    return event.get("action") == "protected_branch.destroy"


def title(event):
    return (
        f"A branch protection was removed from the "
        f"repository [{event.get('repo', '<UNKNOWN_REPO>')}] "
        f"by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
    )
    
```

### Lab 3 Exercise 2

## Lab 4 - Modifying Existing Rules with AWS 

``` json

{
"accountId": "123456789012",
"arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
"createdAt": "2020-02-14T18:12:22.316Z",
"description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
"id": "eeb88ab56556eb7771b266670dddee5a",
"partition": "aws",
"region": "us-east-1",
"schemaVersion": "2.0",
"service": {
	"action": {
		"actionType": "AWS_API_CALL",
		"awsApiCallAction": {
			"affectedResources": {
				"AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"
			},
			"api": "PutRolePolicy",
			"callerType": "Domain",
			"domainDetails": {
				"domain": "cloudformation.amazonaws.com"
			},
			"serviceName": "iam.amazonaws.com"
		}
	},
	"additionalInfo": {},
	"archived": false,
	"count": 1,
	"detectorId": "111111bbbbbbbbbb5555555551111111",
	"eventFirstSeen": "2020-02-14T17:59:17Z",
	"eventLastSeen": "2020-02-14T17:59:17Z",
	"evidence": null,
	"resourceRole": "TARGET",
	"serviceName": "guardduty"
},
"severity": 8,
"title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
"type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
"updatedAt": "2020-02-14T18:12:22.316Z"
}

```


