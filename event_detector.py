# event_detector.py
import boto3
import time
import logging

def detect_privilege_escalation_events(cloudtrail_client):
    try:
        response_iterator = cloudtrail_client.get_paginator('lookup_events').paginate(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateLoginProfile'},
                # Add more relevant event names here
            ],
            StartTime=int(time.time()) - 3600,
            PaginationConfig={'PageSize': 50}
        )
        
        # Process CloudTrail events
        detected_events = []
        for page in response_iterator:
            for event in page.get('Events', []):
                event_name = event.get('EventName')
                user_identity = event.get('UserIdentity', {})
                event_time = event.get('EventTime')
                
                detected_events.append({
                    'event_name': event_name,
                    'user_identity': user_identity.get('Arn'),
                    'event_time': event_time
                })
                
        return detected_events
        
    except boto3.exceptions.Boto3Error as e:
        logging.error(f"An error occurred while interacting with AWS services: {str(e)}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
