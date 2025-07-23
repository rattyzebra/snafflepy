import re
import toml
import os
import logging
import google.generativeai as genai
from dotenv import load_dotenv
# import pprint
import termcolor
import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from impacket.smbconnection import SessionError, SMBConnection
from .file_handling import *

log = logging.getLogger('snafflepy.classifier')

GEMINI_RESULTS = []

def analyze_with_gemini(remote_file, model_name="gemini-2.5-flash"):
    """
    Analyzes a file's content using the Gemini API to find credentials or other sensitive information like PII.
    Returns a rule-like dictionary if credentials are found, otherwise None.
    """
    log.debug(f"Analyzing {remote_file.name} with Gemini...")
    try:
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            log.error("GEMINI_API_KEY not found in .env file.")
            return None

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)

        with open(str(remote_file.tmp_filename), 'rb') as f:
            file_data = f.read().decode('utf-8', errors='ignore')

        prompt = f"Analyze the following file content and identify any potential credentials (e.g., usernames, passwords, API keys, tokens) or PII (credit cards, social security numbers, etc.). For each credential found, describe what it is and what host or service it might belong to. If no credentials are found, say so. Please format your response as a JSON object with a 'credentials' key, which is a list of objects, each with 'type', 'value', and 'context' keys.\n\n--- FILE CONTENT ---\n{file_data}\n--- END FILE CONTENT ---"

        response = model.generate_content(prompt)

        if response.text:
            gemini_text = termcolor.colored("[Gemini]", 'cyan')
            try:
                # Strip markdown JSON block
                json_text = response.text.strip()
                if json_text.startswith("```json"):
                    json_text = json_text[7:]
                if json_text.endswith("```"):
                    json_text = json_text[:-3]
                json_text = json_text.strip()

                # Attempt to parse the JSON response
                gemini_results = json.loads(json_text)
                if "credentials" in gemini_results and gemini_results["credentials"]:
                    log.info(f"{gemini_text} Found potential credentials in {remote_file.name}:")
                    for cred in gemini_results["credentials"]:
                        cred_type = cred.get('type', 'N/A')
                        cred_value = cred.get('value', 'N/A')
                        cred_context = cred.get('context', 'N/A')
                        log.info(f"  - Type: {termcolor.colored(cred_type, 'red')}")
                        GEMINI_RESULTS.append({'file': remote_file.name, 'type': cred_type, 'value': cred_value, 'context': cred_context})
                    
                    # Return a rule so the file gets snaffled
                    return {
                        'RuleName': 'GeminiCredentialFinding',
                        'Triage': 'Red',
                        'Description': 'Credentials identified by Gemini analysis.'
                    }
                else:
                    log.debug(f"{gemini_text} No credentials found in {remote_file.name}")
            except json.JSONDecodeError:
                # Fallback for non-JSON responses
                log.debug(f"{gemini_text} Analysis for {remote_file.name}: {response.text.strip()}")
        else:
            log.warning(f"Gemini returned no response for {remote_file.name}")

    except Exception as e:
        log.error(f"Error during Gemini analysis for {remote_file.name}: {e}")
    
    return None

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
