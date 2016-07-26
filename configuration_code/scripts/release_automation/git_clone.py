#!/usr/bin/env python3

"""
Git Clone Script
Clone a git repository using Python + GitPython
"""
from git import Repo
import logging
import argparse
import re


# Logging
logging.basicConfig(
    level=logging.DEBUG
)


def url_maniupation(url):
    """
    # Manipulate ra_git_repo_url string to drop https and add .git if required
    :param url: Git Repository for getting branches e.g. https://github.com/GeoscienceAustralia/amazonia.git
    :return:
    """
    # Ensure .git extension
    url_dot_git = url + '.git' if url[-4:] != '.git' else url

    # Drop https:// prefix
    pattern = re.compile('^(https://|http://)', re.IGNORECASE)
    short_git_url = pattern.sub('', url_dot_git)

    # Get name of git repo for paths
    git_repo_name = short_git_url.split('/')[-1].split('.')[-2]

    return short_git_url, git_repo_name, url_dot_git

# Argparsing
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--user', '--ra_git_user',
                    help='Name of user to log into https git repo')
parser.add_argument('-p', '--password', '--ra_git_password',
                    help='Password to log into https git repo')
parser.add_argument('-g', '--url', '--ra_git_repo_url',
                    help='URL to clone git repository with e.g. https://github.com/GeoscienceAustralia/amazonia.git '
                         'or https://github.com/GeoscienceAustralia/amazonia.git')
args = parser.parse_args()

# Variables
ra_git_repo_tuple = url_maniupation(args.url)
ra_url_dot_git = ra_git_repo_tuple[2]
ra_git_repo_name = ra_git_repo_tuple[1]
ra_short_git_url = ra_git_repo_tuple[0]
ra_git_user = args.user
ra_git_password = args.password

# Clone Repo
if ra_git_user:
    ra_clone = Repo.clone_from('https://{0}:{1}@{2}'.format(ra_git_user, ra_git_password, ra_short_git_url),
                               ra_git_repo_name)
else:
    ra_clone = Repo.clone_from(args.url, ra_git_repo_name)

logging.info('Cloning {0} from {1}'.format(ra_git_repo_name, ra_url_dot_git))

