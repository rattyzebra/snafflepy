from .utilities import *
from .errors import *

from pathlib import Path
import os
import termcolor
import tempfile
import shutil


# RT: Stolen from manspider - https://github.com/blacklanternsecurity/MANSPIDER


class RemoteFile():
    '''
    Represents a file on an SMB share
    Passed from a spiderling up to its parent spider    
    '''

    def __init__(self, name, share, target, size=0, smb_client=None):

        self.share = share
        self.target = target
        self.name = name
        self.size = size
        self.smb_client = smb_client
        self.classification = None

        # Use a temporary file for downloading
        self.tmp_filename = Path(tempfile.gettempdir()) / (random_string(15) + Path(name).suffix.lower())

    def get(self, smb_client=None):
        '''
        Downloads file to self.tmp_filename

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        '''

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError('Please specify smb_client')

        with open(str(self.tmp_filename), 'wb') as f:
            try:
                smb_client.conn.getFile(self.share, self.name, f.write)
            except Exception as e:
                handle_impacket_error(e, smb_client, self.share, self.name)
                raise FileRetrievalError(
                    f'Error retrieving file "{str(self)}": {str(e)[:150]}')

    def save_to_remotefiles(self, matched_rules):
        '''
        Moves the file from the temporary location to the remotefiles directory
        and logs the matched rules.
        '''
        remotefiles_dir = Path('./remotefiles')
        remotefiles_dir.mkdir(exist_ok=True)
        
        # Sanitize the filename to prevent directory traversal
        sanitized_name = os.path.basename(self.name)
        destination = remotefiles_dir / sanitized_name
        
        # Ensure the destination directory exists
        destination.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(self.tmp_filename), destination)

        rule_names = ", ".join([r['RuleName'] for r in matched_rules])
        # Get the highest triage color
        triage_colors = {"Red": 1, "Orange": 2, "Yellow": 3, "Green": 4, "White": 5}
        highest_triage = "White"
        for r in matched_rules:
            if triage_colors.get(r['Triage'], 5) < triage_colors.get(highest_triage, 5):
                highest_triage = r['Triage']
        
        color = highest_triage
        
        snaffle_text = termcolor.colored(f"[Snaffled][{color}]", color.lower())
        log.info(f"{snaffle_text} {str(self)} (Matched: {rule_names})")

    def __str__(self):

        return f'\\{self.target}\\{self.share}\\{self.name}'

    def __del__(self):
        '''
        Cleans up the temporary file when the object is destroyed.
        '''
        try:
            if os.path.exists(self.tmp_filename):
                os.remove(self.tmp_filename)
        except Exception:
            # Can't do much here, maybe log it
            pass

    
