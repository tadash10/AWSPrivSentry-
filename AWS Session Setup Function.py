# aws_utils.py
import boto3

def create_aws_session(region_name):
    return boto3.Session(region_name=region_name)
