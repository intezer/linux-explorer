import os
import subprocess
import shutil

class Tool(object):
    ''' used for long-running external tools such as yara or chkrootkit '''

    def __init__(self):
        self._proc_object = None
        self._proc_cmdline = []
        self._output_path = os.path.join(os.path.dirname(__file__),
                                         self.__class__.__name__.lower() + '.log')

        if not self._is_installed():
            raise Exception('error: %s not installed' % self.__class__.__name__)

    def _is_installed(self):
        raise NotImplementedError()

    def set_cmdline(self):
        raise NotImplementedError()

    def run(self):
        if not len(self._proc_cmdline):
            raise Exception('error: please use set_cmdline first!')

        if self.status() != 'running':
            self._proc_object = subprocess.Popen(self._proc_cmdline, stdout=open(self._output_path, 'wb'),
                                                 stderr=subprocess.STDOUT)

    def status(self):
        if not self._proc_object:
            return 'not started'

        # set returncode attr
        self._proc_object.poll()

        return 'running' if self._proc_object.returncode == None else self._parse_status(self._proc_object.returncode)

    def _parse_status(self, status):
        ''' override this function to handle different exit codes '''

        return 'done(%d)' % status

    def results(self):
        if not os.path.isfile(self._output_path):
            return '-'

        with open(self._output_path, 'rb') as fh:
            data = fh.read()

        return data[:10 * 1024]  # handle this limit

    def stop(self):
        if self._proc_object:
            self._proc_object.kill()


class YARA(Tool):
    def _is_installed(self):
        return shutil.which('yara')

    def set_cmdline(self, rule_file, dir='/', recursive=True, pid=None):
        if pid:
            self._proc_cmdline = [shutil.which('yara'), rule_file, pid]

        else:
            self._proc_cmdline = [shutil.which('yara')] + ['-r', rule_file, dir] if recursive else [rule_file, dir]


class Chkrootkit(Tool):
    def _is_installed(self):
        return shutil.which('chkrootkit')

    def set_cmdline(self):
        self._proc_cmdline = [shutil.which('chkrootkit')]


class Find(Tool):
    def _is_installed(self):
        return True

    def set_cmdline(self, dir, name):
        self._proc_cmdline = ['/usr/bin/find', dir, '-name', name]
