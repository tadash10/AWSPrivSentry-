import boto3
import time
import logging

# Configure AWS credentials and region
AWS_REGION = 'your_aws_region'
AWS_ACCESS_KEY = 'your_access_key'
AWS_SECRET_KEY = 'your_secret_key'

# Initialize AWS clients
cloudtrail_client = boto3.client('cloudtrail', region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
cloudwatch_client = boto3.client('cloudwatch', region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_privilege_escalation_events():
    try:
        # Search for CloudTrail events related to privilege escalation
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateLoginProfile'},
                # Add more relevant event names here
            ],
            StartTime=int(time.time()) - 3600,  # Search for events in the last hour
            MaxResults=50  # You can adjust the maximum number of results based on your needs
        )
        
        # Process CloudTrail events
        for event in response.get('Events', []):
            event_name = event.get('EventName')
            user_identity = event.get('UserIdentity', {})
            event_time = event.get('EventTime')
            
            # Log and notify about the detected event
            logger.warning(f"Potential privilege escalation detected: {event_name} by {user_identity.get('Arn')} at {event_time}")
            
            # You can add actions to secure the environment here, such as disabling the compromised user's account,
            # revoking their permissions, or triggering an alert to the security team.
    
    except Exception as e:
        logger.error(f"An error occurred while detecting events: {str(e)}")

def main():
    try:
        while True:
            detect_privilege_escalation_events()
            time.sleep(600)  # Check for events every 10 minutes
    except KeyboardInterrupt:
        logger.info("Script terminated by user.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
