#!/usr/bin/env bash
# Release Automation
#   - Bump Version
#   - Create Tag
#
# Assumes git_repo already cloned and cd git_repo already run


print_usage() {
   echo "Usage: sh ./ra.sh -u \$user -p \$password -b \$bump -r \$repo"
   echo "Usage Example: sh ./ra.sh -u my_user -p my_password -b patch -r github.com/organisation/project"
}

INPUT_ERRORS=0


while [ $# -ge 1 ]
do
   key="$1"
   case ${key} in
      -u|--user|--git_user)
         user="$2"
         shift
      ;;
      -p|--password|--git_password)
         password="$2"
         shift
      ;;
      -r|--repo| --repo-url)
         repo="$2"
         shift
      ;;
      -b|--bump|--bumpversion|--bump-version)
         bump="$2"
         shift
      ;;
      *)
         echo "Unknown option ${1}"
         print_usage
         exit 1
      ;;
    esac
    shift
done

if [ -z ${user} ] ; then
   echo "Error: Git Username has not been set"
   : $((INPUT_ERRORS+=1))
fi

if [ -z ${repo} ] ; then
   echo "Error: Git URL has not been set properly"
   echo "Please use github.com/organisation/project.git"
   : $((INPUT_ERRORS+=1))
fi

if [ -z ${password} ] ; then
   echo "Error: Git Password has not been set"
   : $((INPUT_ERRORS+=1))
fi

if [ -z ${bump} ]; then
   echo "Setting Bump Version to Patch Version"
   echo "Please set -b to \"patch\", \"minor\" or \"major\" to specify"
   bump="patch"
fi

if [ "$INPUT_ERRORS" -gt 0 ]; then
   print_usage
   exit ${INPUT_ERRORS}
fi


## Set Orgin
git remote add central https://${user}:${password}@${repo} && echo "!! GIT REMOTE ADD CENTRAL"

## Merge to Master
git fetch central && echo "!! GIT FETCH"                                  # Maybe Remove
git checkout integration && echo "!! GIT CHECKOUT INTEGRATION"
git checkout master && echo "!! GIT CHECKOUT MASTER"
diff=$(git diff master...integration)
echo ${diff}
if [ -z ${diff} ]; then
    git merge integration --no-edit && echo "!! GIT MERGE INTEGRATION"

    ## Bump Integration Version
    git checkout integration && echo "!! GIT CHECKOUT INTEGRATION"
    #bumpversion patch --list --verbose --dry-run
    bumpversion ${bump} --list --verbose && echo "!! BUMPVERSION"

    ## Push Both Commits and Tags
    git push central --all && echo "!! GIT PUSH --ALL"                      # Push to origin?
    git push central --tags && echo "!! GIT PUSH --TAGS"                    # Push to origin?
else
    echo No Changes, Master and Integration is identical
fi