
# Code-to-Cloud: Securing the Software Supply Chain Workshop

This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.



## Lab 1 - Writing Our First Detection

Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection.

### Terms we'll reference

- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)



### Lab 1- Exercise 1

In this exercise, we will create our first detection using Python in Panther. We want to create a medium-priority alert if a new invite to our GitHub organization is sent. You can find a sample log event under "Investigate -> Query Builder" or use this sample event for your unit test. 

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
6. Under "Set Alert Field" set the "Severity" to "Medium"
7. Next scroll down to "Unit Test" and click "Add New" copy and past the above sample JSON or from the "Investigation -> Query Builder" and past.
8. Write a detection with the ```def rule()``` function hint look for the "action" and "operation_type" elements in the JSON


	<details>
		<summary> Sample Okta Event </summary>
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

9. Next let's add more context to the alert using the ```def title``` function so that it says "A new invite was sent to [user] by [actor] for org [org name]


## Lab 2: User priv escalation

##Lab 3: Remove protected branch

##Lab 4: Make public

## Lab 1 - Writing Our First Detection

Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection.

### Terms we'll reference

- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

Sample GitHub Event - Branch Proection Destroy:
  
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
	"required_status_checks_enforcement_level": 0,
	"user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

```

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
