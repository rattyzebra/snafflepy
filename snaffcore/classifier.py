import re
import toml
import os
import logging
# import pprint
import termcolor
try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from impacket.smbconnection import SessionError, SMBConnection
from .file_handling import *

log = logging.getLogger('snafflepy.classifier')


class Matcher:
    def __init__(self, rule):
        self.rule = rule
        self.text_style = termcolor.colored(f"[{self.rule['EnumerationScope']}]", 'light_yellow')

    def match(self, text):
        for pattern in self.rule['WordList']:
            if self._match_pattern(pattern, text):
                return self._handle_match()
        return None

    def _match_pattern(self, pattern, text):
        if self.rule['WordListType'] == "Regex":
            return re.search(str(pattern), str(text))
        elif self.rule['WordListType'] == "EndsWith":
            return re.search(str(pattern + "$"), str(text))
        elif self.rule['WordListType'] == "StartsWith":
            return re.search(str("^" + pattern), str(text))
        elif self.rule['WordListType'] == "Contains":
            return re.search(str(pattern), str(text))
        elif self.rule['WordListType'] == "Exact":
            return re.search(str("^" + pattern + "$"), str(text))
        else:
            log.warning(
                f"{self.rule['RuleName']} has an invalid WordListType - valid values are Regex, EndsWith, StartsWith, Contains, or Exact")
            raise Exception("Invalid WordListType")

    def _handle_match(self):
        if self.rule['MatchAction'] == "Snaffle":
            # Return the rule that was matched
            return self.rule
        else:
            # For 'Discard', log the match and return False
            log.debug(
                f"{self.rule['MatchAction']} matched rule {self.rule['RuleName']}:{self.rule['Description']}")
            if self.rule['MatchAction'] == "Discard":
                return False


class Rules:

    def __init__(self, rules_path=None) -> None:
        self.classifier_rules = []
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []
        self.rules_path = rules_path

    def prepare_classifiers(self):
        if self.rules_path:
            rules_path = self.rules_path
        else:
            rules_path = pkg_resources.files('snaffcore') / 'DefaultRules'
        
        for root, dirs, files in os.walk(str(rules_path)):
            for name in files:
                with open(os.path.join(root, name), 'r') as tfile:
                    toml_loaded = toml.load(tfile)
                for dict_rule in toml_loaded['ClassifierRules']:
                    if dict_rule['EnumerationScope'] == "ShareEnumeration":
                        self.share_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "FileEnumeration":
                        self.file_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "DirectoryEnumeration":
                        self.directory_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "PostMatch":
                        self.postmatch_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "ContentsEnumeration":
                        self.contents_classifiers.append(dict_rule)
                    else:
                        log.warning(
                            f"{dict_rule['RuleName']} is invalid, please check your syntax!")


def classify_file_name(file, rules: Rules):
    matched_rules = []
    for rule in rules.file_classifiers:
        matcher = Matcher(rule)
        result = matcher.match(file.name)
        if isinstance(result, dict):
            matched_rules.append(result)
    return matched_rules


def classify_file_content(file, rules: Rules):
    matched_rules = []
    try:
        with open(str(file.tmp_filename), 'rb') as f:
            file_data = f.read(10000).decode('utf-8', errors='ignore')
            for rule in rules.contents_classifiers:
                matcher = Matcher(rule)
                result = matcher.match(file_data)
                if isinstance(result, dict):
                    # To avoid duplicates if a file is matched by name and content by the same rule
                    if result not in matched_rules:
                        matched_rules.append(result)
    except Exception as e:
        log.error(f"Error reading file content: {e}")
    return matched_rules


def classify_directory(dir, rules: Rules):
    for rule in rules.directory_classifiers:
        matcher = Matcher(rule)
        result = matcher.match(dir)
        if result is not None:
            return result
    return None


def is_interest_share(share, rules: Rules) -> bool:
    for rule in rules.share_classifiers:
        matcher = Matcher(rule)
        result = matcher.match(share)
        if result is not None:
            return result
    return True
