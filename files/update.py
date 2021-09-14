#! /usr/bin/python3
# This script is the reference architecture for this environment with a few deviations
# 1. There is more than one file with a number of other requirements
# 2. The script is not using a default python3 environment that does not require external packages
# https://github.com/KoffieNu/rpm2cvescan/blob/python/rpm2cvescan.py
from typing import Type
import xml.etree.ElementTree as ET
import urllib.request
import bz2
import subprocess
import logging, os
from logging.handlers import SysLogHandler
# Notes:
# This script is developed to support what should be the functionaltiy of the yum update -security flag that does not properly work.
# Unfortunately the CENTOS public repositories do not contain the retired metadata in order to allow the security flag to do anything
# The work around for this capability is to directly query the vulnerability database and pull the relevant RPM data from the oval database.

# Main logging function
log = logging.getLogger(__name__)
log.setLevel(level=os.environ.get("YUM_LOGLEVEL", "INFO"))

# Create handler
handler = SysLogHandler(address='/dev/log')
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

# Create frontend
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Name space prefix in oval definitions
namespace='{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
oval_url = 'https://www.redhat.com/security/data/oval/v2/RHEL7/rhel-7.oval.xml.bz2'
temp_name = '/tmp/rhel-7.oval.xml.bz2'
xml_path = '/tmp/rhel-7.oval.xml'
log.info("Processing Updates for YUM")
log.debug(f"Gathering updates from {oval_url}")
# https://www.redhat.com/security/data/oval/v2/RHEL7/rhel-7.oval.xml.bz2


def downloadcontent(url, downloadpath):
   """ Helper function to use urllib to download large files in blocks """
   webprovider = urllib.request.urlopen(url)
   with open(downloadpath, 'wb') as localcontent:
      file_size_dl = 0
      block_sz = 8192
      while True:
         buffer = webprovider.read(block_sz)
         if not buffer:
            break

         file_size_dl += len(buffer)
         localcontent.write(buffer)

def _pop_letters(char_list):
   """ takes a character list and pops all letters off the front """
   letters = []
   while len(char_list) != 0 and char_list[0].isalpha():
      letters.append(char_list.pop(0))
   log.debug(f"Popped {letters}")
   return letters

def _pop_digits(char_list):
   """ takes a character list and pops all digits off the front """
   digits = []
   while len(char_list) != 0 and char_list[0].isdigit():
      digits.append(char_list.pop(0))
   log.debug(f"Popped {digits}")
   return digits

def _compareblocks(block_a, block_b):
   """ Returns either True, False, or None if the block_a is greater than block_b """
   if len(block_b) == 0:
      return False
   elif len(block_a) == 0:
      return True
   if block_a == block_b:
      return None
   if block_a[0].isdigit() and block_b[0]:
      return int(''.join(block_a)) < int(''.join(block_b))
   else:
      return block_a < block_b

def compareversions(installed, vulnerable):
   """ Returns True if the installed version needs updated """
   # Immediately return if the installed is equal to vulnerable
   if installed == vulnerable:
      return True
   
   # Define some constant variables
   chars_installed, chars_vulnerable = list(installed), list(vulnerable)
   break_character = ['.', '-', ':', '_']
   retry_count = 0

   # Loop as liong as we have variables
   while len(chars_installed) != 0 and len(chars_vulnerable) != 0:
      # Break if we loop more than 3 times something is wrong
      if retry_count > 3:
         break
      # Lets remove the break characters
      if chars_installed[0] in break_character and chars_vulnerable[0] in break_character:
         chars_vulnerable.pop(0)
         chars_installed.pop(0)
         retry_count = 0
      # Set our pop function
      first_is_digit = chars_installed[0].isdigit()
      pop_func = _pop_digits if first_is_digit else _pop_letters
      # Grab the blocks
      block_installed, block_vulnerable = pop_func(chars_installed), pop_func(chars_vulnerable)
      # Define the result
      result = _compareblocks(block_installed, block_vulnerable)
      # Return our result if we are not invalid
      if result != None:
         return result
      else:
         retry_count += 1


class oval_rpm:
   """ RPM model to compare versions """
   def __init__(self, name, version=None, build=None, epoch = 0) -> None:
      self.name = name
      self.version = version
      self.build = build.replace('_7', '')
      if epoch != '(none)':
         self.epoch = epoch
      else:
         self.epoch = 0

   def __lt__(self, other):
      """Override the default Greater or equal behavior"""
      if isinstance(other, self.__class__):
         if self.name == other.name:
            return compareversions(f"{self.epoch}:{self.version}-{self.build}", f"{other.epoch}:{other.version}-{other.build}")
         else:
            return False
      else:
         return NotImplemented

   def __str__(self) -> str:
       return f"{self.name} - {self.epoch}:{self.version}-{self.build}"

class oval_cve:
   """ basic model for CVE """
   def __init__(self, name, cvss, score):
      self.name = name
      self.cvss = int(cvss)
      self.score = float(score)

class oval_patch:
   """ Basic Model for patch error """
   def __init__(self, name, version, patchable=True):
      self.name = name
      self.version = int(version)
      self.rhalist = []
      self.cvelist = []
      self.rpmlist = []
      self.patchable = patchable

   def __str__(self) -> str:
      return f"{self.name} - {self.version} - Patchable: {self.patchable}"

def parseversion(version):
   """ Extract the epoch, build, and package from the rpm build """
   epoch = version.split(':')[0]
   build = version.split('-')[1]
   packageversion = version.split(':')[1].split('-')[0]
   return packageversion, build, epoch

def recurse_criteria(my_criterion):
   """ Read through all the criteria and extract the package name from the OVAL Test """
   my_rpmlist = []
   if my_criterion.tag == namespace+'criteria':
      for my_criteria in my_criterion:
         my_rpmlist += recurse_criteria(my_criteria)
   elif my_criterion.tag == namespace+'criterion':
      comment = my_criterion.attrib['comment']
      if 'Red Hat' not in comment:
         if 'is installed' in comment:
            splitcomment = comment.split()
            my_rpmlist.append(oval_rpm(splitcomment[0]))
         if 'is earlier than' in comment:
            splitcomment = comment.split()
            packageversion, build, epoch = parseversion(splitcomment[-1])
            my_rpmlist.append(oval_rpm(splitcomment[0], packageversion, build, epoch))

   return my_rpmlist

def get_patchlist(oval_path):
   """ Extract all CVE's and RHSA's from the oval definitions """
   my_patchlist = []
   xml_tree = ET.parse(oval_path)
   oval_definitions = xml_tree.getroot()
   for oval_subset in oval_definitions:
      if oval_subset.tag == namespace+'definitions':
            for oval_definition in oval_subset:
               patch_definition = oval_definition.attrib
               current_patch = oval_patch(patch_definition['id'].split(':')[-1], patch_definition['version'])
               log.debug(f"Processing {patch_definition['id'].split(':')[-1]}")
               for patch_data in oval_definition:
                  # Get CVE ID
                  if patch_data.tag == namespace+'metadata':
                     for metadata_data in patch_data:
                        if metadata_data.tag.endswith('reference'):
                           if metadata_data.attrib['source'] != 'CVE':
                              current_patch.rhalist.append(metadata_data.attrib['ref_id'])
                              log.debug(f"Asocciated RHSA: {metadata_data.attrib['ref_id']}")

                        if metadata_data.tag.endswith('description') and metadata_data.text !=None:
                           if 'This issue is not currently planned to be addressed in future updates' in metadata_data.text:
                              current_patch.patchable = False
                           if 'this issue is not currently planned to be addressed in future releases' in metadata_data.text:
                              current_patch.patchable = False

                     # get CVSS score of the CVE with this patch
                     if metadata_data.tag == namespace+'advisory':
                        for advisory_data in metadata_data:
                           # Assumption: CVSS3 score takes president over CVSS2
                           if advisory_data.tag == namespace+'cve':
                              if 'cvss3' in advisory_data.keys():
                                 cve = advisory_data.attrib['href'].split('/')[-1]
                                 score_txt = advisory_data.attrib['cvss3'].split('/')[0]
                                 score = float(score_txt)

                                 current_patch.cvelist.append(oval_cve(cve, 3, score))
                                 log.debug(f"Asocciated CVE3: {cve} Ranking {score}")

                              elif 'cvss2' in advisory_data.keys():
                                 cve = advisory_data.attrib['href'].split('/')[-1]
                                 score_txt = advisory_data.attrib['cvss2'].split('/')[0]
                                 score = float(score_txt)

                                 current_patch.cvelist.append(oval_cve(cve, 2, score))
                                 log.debug(f"Asocciated CVE2: {cve} Ranking {score}")
                              else:
                                 cve = advisory_data.attrib['href'].split('/')[-1]
                                 if 'impact' in advisory_data.keys():
                                       if advisory_data.attrib['impact'] == 'critical':
                                          score = 9.9
                                       elif advisory_data.attrib['impact'] == 'important':
                                          score = 8.9
                                       elif advisory_data.attrib['impact'] == 'moderate':
                                          score = 6.9
                                       elif advisory_data.attrib['impact'] == 'low':
                                          score = 3.9
                                       else:
                                          score = 0.0
                                 else:
                                       score = -0.1
                                 current_patch.cvelist.append(oval_cve(cve, 1, score))
                                 log.debug(f"Asocciated CVEU: {cve} Ranking {score}")
                  # Weed through Criteria to get package name
                  if patch_data.tag == namespace+'criteria':
                     for criteria in patch_data:
                        current_patch.rpmlist += recurse_criteria(criteria)
               my_patchlist.append(current_patch)
               del current_patch

   return my_patchlist

def get_system_rpmlist():
   """ Return all the RPM's that are installed on the vm """
   my_system_rpmlist = []
   my_system_rpmnames = []

   cmd = ['/usr/bin/rpm \
         -qa --queryformat "%{NAME} %{VERSION} %{RELEASE} %{EPOCH}\\n"']
   p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True)

   out, err = p.communicate()
   p_status = p.wait()
   # with open('package.txt', 'r') as file:
   #    lines = file.readlines()
   lines = out.decode().split('\n')


   for line in lines:
      if line != '':
        txtrpm = line.split()
        my_system_rpmlist.append(oval_rpm(txtrpm[0], txtrpm[1], txtrpm[2], txtrpm[3]))
        my_system_rpmnames.append(txtrpm[0])
   return my_system_rpmlist, my_system_rpmnames


def returnpatches(ovalpath):
   # Fetch system RPMS
   installed_packages, my_system_rpmnames = get_system_rpmlist()
   # Get the vulnerable packages
   vulnerable_packages = get_patchlist(ovalpath)
   # Initalize the vulnerability list
   installed_vulnerable = []
   # Quickly find the CVE's Applicable to this System
   for vulnerability in vulnerable_packages:
      for rpm in vulnerability.rpmlist:
         if rpm.name in my_system_rpmnames:
            installed_vulnerable.append(vulnerability)
   # TODO: Write this so that we can have a local state

   patches = {}
   # Packages that have already been updated
   patches['patched'] = []
   # List of RPM's to update
   patches['rpmupdate'] = []
   # list of CVE's that correspond to those packages
   patches['cves'] = []

   for vuln in installed_vulnerable:
      for rpm in vuln.rpmlist:
         for package in installed_packages:
            if package.name == rpm.name:
               if package < rpm:
                  patches['rpmupdate'].append(package)
                  patches['cves'].append(rpm)
               else:
                  patches['patched'].append(package)
   return patches

# Downloads the file
downloadcontent(oval_url, temp_name)

# Extract the file out to processing
with bz2.open(temp_name) as f:
   with open(xml_path, 'wb') as output:
      output.write(f.read())
# Parse the patches out of the Oval file
patchconstruct = returnpatches(xml_path)
updatelist = []
# Add the unique patches to the update list
log.info(f"Found {len(patchconstruct['rpmupdate'])} RPM's that need updated")
for patch in patchconstruct['rpmupdate']:
   name = patch.name
   if name not in updatelist:
        log.info(f"Updating {name}")
        updatelist.append(name)
if len(updatelist) > 0:
    # Print the relevant command to run so we update all the records
    updatecmd = ['sudo', 'yum', 'update', '-y'] + updatelist
    subprocess.run(updatecmd)
else:
    log.info("System Fully up to date")