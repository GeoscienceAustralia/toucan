#!/usr/bin/env python3

"""
Git Diff Script
Enable git diff comparsions between two branches with a possibility to exclude files via a Python set().
"""
from git import Repo, GitCommandError
from bumpversion import main as bump
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
parser.add_argument('-r', '--remote', '--ra_remote',
                    default='central',
                    help='Name of remote to add e.g. central or origin')
parser.add_argument('-i', '--bi', '--ra_branch_integration',
                    default='integration',
                    help='Name of branch with new material')
parser.add_argument('-m', '--bm', '--ra_branch_master',
                    default='master',
                    help='Name of original branch to merge new material into e.g. master')
parser.add_argument('-u', '--user', '--ra_git_user',
                    help='Name of user to log into https git repo')
parser.add_argument('-p', '--password', '--ra_git_password',
                    help='Password to log into https git repo')
parser.add_argument('-g', '--url', '--ra_git_repo_url',
                    help='URL to clone git repository with e.g. https://github.com/GeoscienceAustralia/amazonia.git '
                         'or https://github.com/GeoscienceAustralia/amazonia.git')
parser.add_argument('-b', '--bump', '--ra_bump_level',
                    default='patch',
                    help='Password to log into https git repo')
parser.add_argument('-x', '--exclude', '--ra_excluded_diff_files',
                    nargs='*',
                    help='List of file names to exclude from diff, e.g ".bumpversion.cfg setup.py sonar-project.properties"')
args = parser.parse_args()

# Variables
ra_git_repo_tuple = url_maniupation(args.url)
ra_url_dot_git = ra_git_repo_tuple[2]
ra_git_repo_name = ra_git_repo_tuple[1]
ra_short_git_url = ra_git_repo_tuple[0]
ra_bump_level = args.bump
ra_remote = args.remote
ra_branch_integration = args.bi
ra_branch_master = args.bm
ra_git_user = args.user
ra_git_password = args.password
ra_excluded_diff_files = args.exclude

# Initialise Repo
repo = Repo(ra_git_repo_name)
git = repo.git
logging.info('Cloning {0} from {1}'.format(ra_git_repo_name, ra_url_dot_git))

# Set Remote Orgin
try:
    if ra_git_user:
        central = git.remote('add',
                             ra_remote,
                             'https://{0}:{1}@{2}'.format(ra_git_user, ra_git_password, ra_short_git_url))
    else:
        central = git.remote('add',
                             ra_remote,
                             ra_url_dot_git)
    logging.info('Setup Remote: {0}'.format(ra_remote))
except GitCommandError:
    logging.info('Remote {0} already exists'.format(ra_remote))

# Fetching Remote
git.fetch(ra_remote)
logging.info('Fetching Remote: {0}'.format(ra_remote))

# Checkout Integration
git.checkout(ra_branch_integration)
logging.info('Checking out branch: {0}'.format(ra_branch_integration))

# Checkout Master
git.checkout(ra_branch_master)
logging.info('Checking out branch: {0}'.format(ra_branch_master))

# Check Diff
ra_git_diff = git.diff(''.join([ra_branch_master, '...', ra_branch_integration]), '--name-only')
ra_split_diff = ra_git_diff.split()
logging.info('Excluded Files are {0}'.format(ra_excluded_diff_files))
logging.info('Diff Files are {0}'.format(ra_split_diff))
logging.info('Generating git diff {0}...{1} --name-only'.format(ra_branch_master, ra_branch_integration))

if set(ra_split_diff) == set(ra_excluded_diff_files):
    logging.info('Git diff results: only excluded files {0}'.format(ra_excluded_diff_files))
    exit(1)
