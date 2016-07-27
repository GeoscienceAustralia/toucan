#!/usr/bin/env python3

"""
Release Automation Script
This will:
  Merge integration into master (assuming those are the name of the two branches you want to use)
  Bump the version on the integration branch
"""
from git import Repo, GitCommandError
from bumpversion import main as bump
import logging
import argparse
import re
import os

# Logging
logging.basicConfig(
    level=logging.INFO
)


def url_maniupation(url):
    """
    # Manipulate ra_git_repo_url string to drop https and add .git if required
    :param url: Git Repository for getting branches e.g. https://github.com/GeoscienceAustralia/amazonia.git
    :return: Tuple of url without https://, name of application from git repo, full url with '.git' at the end
    """
    # Ensure .git extension
    um_url_dot_git = url + '.git' if url[-4:] != '.git' else url

    # Drop https:// prefix
    pattern = re.compile('^(https://|http://)', re.IGNORECASE)
    um_short_git_url = pattern.sub('', um_url_dot_git)

    # Get name of git repo for paths
    um_git_repo_name = um_short_git_url.split('/')[-1].split('.')[0]

    return um_short_git_url, um_git_repo_name, um_url_dot_git


def clone_repo(url, ra_git_user, ra_git_password, ra_short_git_url, ra_git_repo_name, ra_url_dot_git):
    """
    Clone Repo
    :param url: Git Repository for getting branches e.g. https://github.com/GeoscienceAustralia/amazonia.git
    :param ra_git_user: Git user used to login to repository
    :param ra_git_password: Git password for git user to log into repository
    :param ra_short_git_url: Git url without https://
    :param ra_git_repo_name: Name of application from git repository
    :param ra_url_dot_git: Full git url with '.git' at the end
    :return: Git Repo Clone object
    """
    try:
        if ra_git_user:
            logging.debug('Cloning {0} from {1}'.format(ra_git_repo_name, ra_url_dot_git))
            ra_clone = Repo.clone_from('https://{0}:{1}@{2}'.format(ra_git_user, ra_git_password, ra_short_git_url),
                                       ra_git_repo_name)
        else:
            logging.debug('Cloning {0} from {1}'.format(ra_git_repo_name, ra_url_dot_git))
            ra_clone = Repo.clone_from(url, ra_git_repo_name)

        return ra_clone

    except GitCommandError:
        logging.warning('Repo {0} already exists'.format(ra_git_repo_name))


def git_init(ra_git_repo_name, ra_url_dot_git):
    """
    Initialise Repo
    :param ra_git_repo_name: Name of application from git repository
    :param ra_url_dot_git: Full git url with '.git' at the end
    :return: Git Repo object
    """
    logging.info('Initialise Repo {0} from {1}'.format(ra_git_repo_name, ra_url_dot_git))
    repo = Repo(ra_git_repo_name)
    git = repo.git

    logging.debug('Fetching Remote'.format())
    git.fetch()

    return git


def merge_2_master(git, ra_branch_integration, ra_branch_master):
    """
    Merge Integration to Master
    :param git: Git Repo Clone object
    :param ra_branch_integration: Integration Branch to merge changes from
    :param ra_branch_master: Master Branch to merge changes to
    """
    logging.debug('Checking out branch: {0}'.format(ra_branch_integration))
    git.checkout(ra_branch_integration)

    # Checkout Master
    logging.debug('Checking out branch: {0}'.format(ra_branch_master))
    git.checkout(ra_branch_master)

    # Merge to Master
    logging.info('Merging {0} into {1}'.format(ra_branch_integration, ra_branch_master))
    git.merge(ra_branch_integration,
              '--no-edit')


def bumpversion(git, ra_branch_integration, ra_git_repo_name, ra_bump_level):
    """

    :param git: Git Repo Clone object
    :param ra_branch_integration: Integration Branch to merge changes from
    :param ra_git_repo_name: Name of application from git repository
    :param ra_bump_level: Arguments to pass into bump version such as patch, minor or major
    """
    # Checkout Integration
    logging.debug('Checking out branch: {0}'.format(ra_branch_integration))
    git.checkout(ra_branch_integration)

    # Bump Integration Version
    logging.debug('Changed into folder: {0}'.format(ra_git_repo_name))
    os.chdir('/'.join([os.getcwd(), ra_git_repo_name]))

    logging.info('Bumping {0} Version on : {1}'.format(ra_bump_level.upper(), ra_branch_integration))
    bump([ra_bump_level,
          '--list'])


def push_commits_and_tags(git, ra_branch_integration, ra_branch_master):
    """
    Push Commits from all branches and push all tags
    :param git: Git Repo Clone object
    :param ra_branch_integration: Integration Branch to merge changes from
    :param ra_branch_master: Master Branch to merge changes to
    """
    # Push Both Commits
    logging.info('Pushing {0} and {1} branches'.format(ra_branch_integration, ra_branch_master))
    git.push('--all')

    # Push Tags
    logging.info('Pushing new tags')
    git.push('--tags')


def main():
    """
    Manage argumenet parsing and stage execution
    """
    # Argparsing
    parser = argparse.ArgumentParser()
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
                        help='URL to clone git repository with e.g. https://github.com/GeoscienceAustralia/amazonia.git'
                             'or https://github.com/GeoscienceAustralia/amazonia')
    parser.add_argument('-b', '--bump', '--ra_bump_level',
                        default='patch',
                        help="Level of bump, e.g. 'patch', 'minor', 'major'")
    args = parser.parse_args()

    # Variables
    url = args.url
    git_repo_tuple = url_maniupation(args.url)
    url_dot_git = git_repo_tuple[2]
    git_repo_name = git_repo_tuple[1]
    short_git_url = git_repo_tuple[0]
    bump_level = args.bump
    branch_integration = args.bi
    branch_master = args.bm
    git_user = args.user
    git_password = args.password

    # Release Automation Stages
    logging.info('Starting Release Automation')
    clone_repo(url, git_user, git_password, short_git_url, git_repo_name, url_dot_git)
    git = git_init(git_repo_name, url_dot_git)
    merge_2_master(git, branch_integration, branch_master)
    bumpversion(git, branch_integration, git_repo_name, bump_level)
    push_commits_and_tags(git, branch_integration, branch_master)

if __name__ == '__main__':
    main()
