# aws_utils.py
def create_cloudtrail_client(aws_session):
    return aws_session.client('cloudtrail')
