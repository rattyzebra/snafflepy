import sys
import os
import termcolor

from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE
from .smb import * 
from .utilities import *
from .file_handling import *
from .classifier import *
from .errors import *
from .classifier import analyze_with_gemini

log = logging.getLogger('snafflepy')


def begin_snaffle(options):
    snaff_rules = Rules(options.rules)
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    if options.exclude:
        try:
            import re
            options.exclude_regex = re.compile(options.exclude)
        except re.error as e:
            log.error(f"Invalid regex for --exclude: {e}")
            sys.exit(1)
    else:
        options.exclude_regex = None

    unc_targets = [t for t in options.targets if isinstance(t, tuple) and t[0] == 'unc']
    normal_targets = [t for t in options.targets if not (isinstance(t, tuple) and t[0] == 'unc')]

    if unc_targets:
        log.info("Found UNC paths, targeting them directly.")
        for _, server, share, folder in unc_targets:
            log.info(f"Snaffling UNC path: \\{server}\\{share}\\{folder}")
            smb_client = SMBClient(server, options.username, options.password, options.domain, options.hash)
            if not smb_client.login():
                log.error(f"Unable to login to {server}")
                continue
            
            found_share = False
            for share_name in smb_client.shares:
                if share_name.lower() == share.lower():
                    found_share = True
                    log.info(f"Found matching share '{share_name}', beginning snaffle.")
                    snaffle_share(share_name, folder, smb_client, options, snaff_rules)
                    break
            
            if not found_share:
                log.error(f"Could not find the specified share '{share}' on server {server}")

    if not normal_targets:
        return

    options.targets = normal_targets

    # Automatically get domain from target if not provided
    if not options.domain:
        options.domain = get_domain(normal_targets[0])
        if options.domain == "":
            sys.exit(2)

    domain_names = []
    if options.disable_computer_discovery:
        log.info("Computer discovery is turned off. Snaffling will only occur on the host(s) specified.")
        options.targets = normal_targets
    else:
        login = access_ldap_server(normal_targets[0], options.username, options.password)
        domain_names = list_computers(login, options.domain)
        options.targets = normal_targets
        for target in domain_names:
            log.info(f"Found {target}, adding to targets to snaffle...")
            try:
                options.targets.append(target)
            except Exception as e:
                log.debug(f"Exception: {e}")
                log.warning(f"Unable to add {target} to targets to snaffle")
                continue

    if options.go_loud:
        log.warning("[GO LOUD ACTIVATED] Enumerating all shares for all files...")
    if options.no_download:
        log.warning("[no-download] is turned on, skipping SSN check...")

    for target in options.targets:
        smb_client = SMBClient(target, options.username, options.password, options.domain, options.hash)
        if not smb_client.login():
            log.error(f"Unable to login to {target}")
            continue

        for share in smb_client.shares:
            try:
                if not options.go_loud:
                    if not is_interest_share(share, snaff_rules):
                        log.debug(f"{share} matched a Discard rule, skipping files inside of this share...")
                        continue
                
                snaffle_share(share, "", smb_client, options, snaff_rules)
                                
            except FileListError as e:
                log.error(f"Cannot list files at {share} {e}")

def snaffle_share(share, path, smb_client, options, snaff_rules):
    try:
        files = smb_client.ls(share, path)
    except FileListError as e:
        log.error(f"Cannot list files at {share}{path} {e}")
        return

    for file in files:
        size = file.get_filesize()
        name = file.get_longname()
        new_path = os.path.join(path, name)

        if options.exclude_regex and options.exclude_regex.search(new_path):
            log.debug(f"Excluding {new_path} due to exclusion regex.")
            continue

        remote_file = RemoteFile(new_path, share, smb_client.server, size, smb_client)

        if file.is_directory():
            if options.go_loud:
                dir_text = termcolor.colored("[Directory]", 'light_blue')
                log.info(f"{dir_text} \\{smb_client.server}\\{share}\\{new_path}")
            if classify_directory(new_path, snaff_rules) is not False:
                snaffle_share(share, new_path, smb_client, options, snaff_rules)
        else:
            if options.verbose:
                log.info(f"[*] Found file: {str(remote_file)}")
            
            if options.go_loud:
                try:
                    file_text = termcolor.colored("[File]", 'green')
                    if not options.no_download:
                        remote_file.get(smb_client)
                        remote_file.save_to_remotefiles([]) # No rules for go_loud
                    log.info(
                        f"{file_text} \\{smb_client.server}\\{share}\\{new_path}")

                except FileRetrievalError as e:
                    log.error(f"Error retrieving file: {remote_file.name} ({e})")
                    
            elif size < options.max_file_snaffle and options.classification:
                try:
                    matched_rules = []
                    
                    # 1. Classify by filename
                    name_rules = classify_file_name(remote_file, snaff_rules)
                    matched_rules.extend(name_rules)
                    
                    # 2. Download and classify by content
                    file_downloaded = False
                    if not options.no_download:
                        try:
                            remote_file.get(smb_client)
                            file_downloaded = True
                        except FileRetrievalError as e:
                            log.error(f"Error retrieving file for content scan: {remote_file.name} ({e})")

                    if file_downloaded:
                        content_rules = classify_file_content(remote_file, snaff_rules)
                        if options.gemini:
                            gemini_rule = analyze_with_gemini(remote_file, options.gemini_model)
                            if gemini_rule:
                                matched_rules.append(gemini_rule)
                        # Add new unique rules
                        for rule in content_rules:
                            if rule not in matched_rules:
                                matched_rules.append(rule)
                    
                    # 3. If we have any matches, save the file and report
                    if matched_rules:
                        if not options.no_download:
                            remote_file.save_to_remotefiles(matched_rules)
                        else:
                            # If no_download is on, we just print the info without saving
                            rule_names = ", ".join([r['RuleName'] for r in matched_rules])
                            triage_colors = [r['Triage'] for r in matched_rules]
                            color = triage_colors[0] if triage_colors else 'white'
                            snaffle_text = termcolor.colored("[Snaffle Match]", str(color).lower())
                            log.info(f"{snaffle_text} {str(remote_file)} (Matched: {rule_names})")

                except Exception as e:
                    log.error(f"An unexpected error occurred during classification of {remote_file.name}: {e}")

                
           

def access_ldap_server(ip, username, password):
    # log.info("Accessing LDAP Server")
    server = Server(ip, get_info=DSA)
    try:
        conn = Connection(server, username, password)
        # log.debug(server.schema)

        if not conn.bind():
            log.critical(f"Unable to bind to {server}")
            return None
        return conn

    except Exception as e:
        log.critical(f'Error logging in to {ip}')
        log.info("Trying guest session... ")

        try:
            conn = Connection(server, user='Guest', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server} as {username}")
                return None
            return conn

        except Exception as e:
            log.critical(f'Error logging in to {ip}, as {username}')
            log.info("Trying null session... ")

            conn = Connection(server, user='', password='')
            if not conn.bind():
                log.critical(f"Unable to bind to {server}")
                return None
            return conn

# 2nd snaffle step, finding additional targets from original target via LDAP queries


def list_computers(connection: Connection, domain):
    dn = get_domain_dn(domain)
    if connection is None:
        log.critical("Connection is not established")
        sys.exit(2)

    try:
        connection.search(search_base=dn, search_filter='(&(objectCategory=Computer)(name=*))',
                          search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)
        domain_names = []

        for entry in connection.entries:
            sep = str(entry).strip().split(':')
            # Sometimes there's no dNSHostName
            if len(sep) == 7:
                domain_names.append(sep[6])

        return domain_names

    except Exception as e:
        log.critical(f"Unable to list computers: {e}")
        return None