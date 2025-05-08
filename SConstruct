# MIT License
#
# Copyright The SCons Foundation
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# The following code was extracted from SCons 4.9.1 and modified by
# Joseph C. Brill.
#
# The purpose of this SConstruct is to call vswhere to find a VS2017+ msvc
# installation and to call the default msvc batch file using a "pure" python
# implementation that does not rely on SCons.
#
# This simplified implementation is intended to be close as possible to the
# SCons behavior with respect to calling vswhere and invoking the msvc batch
# files. However, non-trivial msvc initialization code was removed for VS2015
# and earlier (i.e., registry based detection).
#
# The logging output file is the only file written from the SConstruct file.

import json
import logging
import os
import platform
import re
import string
import subprocess
import sys
import time
import winreg

from collections import namedtuple
from functools import cmp_to_key

DefaultEnvironment(tools=[])

# TEST_VCVARS = True:  run vcvars batch file
# TEST_VCVARS = False: run ext dir batch files

TEST_VCVARS = True

# TEST_NEWENV = True:  modified environment
# TEST_NEWENV = False: scons environment

TEST_DEVENV = True
TEST_NEWENV = True

_SCONS_ITERATIONS = 2

_EXT_ITERATIONS = 5
_EXT_ELAPSED_TOLERANCE = 1.0

### SCons Modified Source Code Begin

LOGLEVEL = logging.INFO

UNDEFINED = object()

def _check_logfile(logfile):
    if logfile and '"' in logfile:
        err_msg = (
            "SCONS_MSCOMMON_DEBUG value contains double quote character(s)\n"
            f"  SCONS_MSCOMMON_DEBUG={logfile}"
        )
        raise RuntimeError(err_msg)
    return logfile

def logger_setup():

    root = logging.getLogger()

    logfile = _check_logfile(os.environ.get('SCONS_MSCOMMON_DEBUG'))
    if logfile:

        root.setLevel(LOGLEVEL)

        if logfile == '-':
            log_handler = logging.StreamHandler(sys.stdout)
        else:
            try:
                log_handler = logging.FileHandler(filename=logfile)
            except (OSError, FileNotFoundError) as e:
                err_msg = (
                    "Could not create logfile, check SCONS_MSCOMMON_DEBUG\n"
                    f"  SCONS_MSCOMMON_DEBUG={LOGFILE}\n"
                    f"  {e.__class__.__name__}: {str(e)}"
                )
                raise RuntimeError(err_msg)

        log_handler.setLevel(LOGLEVEL)

        log_format=(
            '%(relativeCreated)05dms'
            ':%(filename)s'
            ':%(funcName)s'
            '#%(lineno)s'
            ': %(message)s'
        )

        log_formatter = logging.Formatter(log_format)

        log_handler.setFormatter(log_formatter)

        root.addHandler(log_handler)

logger_setup()

_VSWHERE_EXE = "vswhere.exe"
_VSWHERE_EXEGROUP_MSVS = [os.path.join(p, _VSWHERE_EXE) for p in [
    # For bug 3333: support default location of vswhere for both
    # 64 and 32 bit windows installs.
    # For bug 3542: also accommodate not being on C: drive.
    os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer"),
    os.path.expandvars(r"%ProgramFiles%\Microsoft Visual Studio\Installer"),
]]
_VSWHERE_EXECUTABLES = [exe for exe in _VSWHERE_EXEGROUP_MSVS if os.path.exists(exe)]

def vswhere_executable():

    logging.debug("")

    vswhere_exe = _VSWHERE_EXECUTABLES[0]
    logging.debug("vswhere_exe=%r", vswhere_exe)

    return vswhere_exe

def vswhere_query_json_output(vswhere_exe, vswhere_args):

    logging.debug("")

    vswhere_json = None

    once = True
    while once:
        once = False
        # using break for single exit (unless exception)

        vswhere_cmd = [vswhere_exe] + vswhere_args + ['-format', 'json', '-utf8']
        logging.debug("running: %s", vswhere_cmd)

        try:
            cp = subprocess.run(vswhere_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except OSError as e:
            errmsg = str(e)
            logging.warning("%s: %s", type(e).__name__, errmsg)
            break
        except Exception as e:
            errmsg = str(e)
            logging.warning("%s: %s", type(e).__name__, errmsg)
            raise

        if not cp.stdout:
            logging.warning("no vswhere information returned")
            break

        vswhere_output = cp.stdout.decode('utf8', errors='replace')
        if not vswhere_output:
            logging.warning("no vswhere information output")
            break

        try:
            vswhere_output_json = json.loads(vswhere_output)
        except json.decoder.JSONDecodeError:
            logging.warning("json decode exception loading vswhere output")
            break

        vswhere_json = vswhere_output_json
        break

    logging.debug('vswhere_json=%s, vswhere_exe=%r', bool(vswhere_json), vswhere_exe)

    return vswhere_json

# vswhere query:
#    map vs major version to vc version (no suffix)
#    build set of supported vc versions (including suffix)

_VSWHERE_VSMAJOR_TO_VCVERSION = {}
_VSWHERE_SUPPORTED_VCVER = set()

for vs_major, vc_version, vc_ver_list in (
    ('17', '14.3', None),
    ('16', '14.2', None),
    ('15', '14.1', ['14.1Exp']),
):
    _VSWHERE_VSMAJOR_TO_VCVERSION[vs_major] = vc_version
    _VSWHERE_SUPPORTED_VCVER.add(vc_version)
    if vc_ver_list:
        for vc_ver in vc_ver_list:
            _VSWHERE_SUPPORTED_VCVER.add(vc_ver)

# vwhere query:
#    build of set of candidate component ids
#    preferred ranking: Enterprise, Professional, Community, BuildTools, Express
#      Ent, Pro, Com, BT, Exp are in the same list
#      Exp also has it's own list
#    currently, only the express (Exp) suffix is expected

_VSWHERE_COMPONENTID_CANDIDATES = set()
_VSWHERE_COMPONENTID_RANKING = {}
_VSWHERE_COMPONENTID_SUFFIX = {}
_VSWHERE_COMPONENTID_SCONS_SUFFIX = {}

for component_id, component_rank, component_suffix, scons_suffix in (
    ('Enterprise',   140, 'Ent', ''),
    ('Professional', 130, 'Pro', ''),
    ('Community',    120, 'Com', ''),
    ('BuildTools',   110, 'BT',  ''),
    ('WDExpress',    100, 'Exp', 'Exp'),
):
    _VSWHERE_COMPONENTID_CANDIDATES.add(component_id)
    _VSWHERE_COMPONENTID_RANKING[component_id] = component_rank
    _VSWHERE_COMPONENTID_SUFFIX[component_id] = component_suffix
    _VSWHERE_COMPONENTID_SCONS_SUFFIX[component_id] = scons_suffix

_MSVCInstance = namedtuple('_MSVCInstance', [
    'vc_path',
    'vc_version',
    'vc_version_numeric',
    'vc_version_scons',
    'vc_release',
    'vc_component_id',
    'vc_component_rank',
    'vc_component_suffix',
])

class MSVCInstance(_MSVCInstance):

    @staticmethod
    def msvc_instances_default_order(a, b):
        # vc version numeric: descending order
        if a.vc_version_numeric != b.vc_version_numeric:
            return 1 if a.vc_version_numeric < b.vc_version_numeric else -1
        # vc release: descending order (release, preview)
        if a.vc_release != b.vc_release:
            return 1 if a.vc_release < b.vc_release else -1
        # component rank: descending order
        if a.vc_component_rank != b.vc_component_rank:
            return 1 if a.vc_component_rank < b.vc_component_rank else -1
        return 0

def vswhere_msvc_instances(vswhere_json):

    logging.debug("")
    msvc_instances = []

    seen_root = set()
    for instance in vswhere_json:

        # print(json.dumps(instance, indent=4, sort_keys=True))

        installation_path = instance.get('installationPath')
        if not installation_path or not os.path.exists(installation_path):
            continue

        vc_path = os.path.join(installation_path, 'VC')
        if not os.path.exists(vc_path):
            continue

        vc_root = os.path.normpath(os.path.abspath(vc_path))
        if vc_root in seen_root:
            continue
        seen_root.add(vc_root)

        installation_version = instance.get('installationVersion')
        if not installation_version:
            continue

        vs_major = installation_version.split('.')[0]
        if not vs_major in _VSWHERE_VSMAJOR_TO_VCVERSION:
            logging.debug('ignore vs_major: %s', vs_major, extra=cls.debug_extra)
            continue

        vc_version = _VSWHERE_VSMAJOR_TO_VCVERSION[vs_major]

        product_id = instance.get('productId')
        if not product_id:
            continue

        component_id = product_id.split('.')[-1]
        if component_id not in _VSWHERE_COMPONENTID_CANDIDATES:
            logging.debug('ignore component_id: %s', component_id, extra=cls.debug_extra)
            continue

        component_rank = _VSWHERE_COMPONENTID_RANKING.get(component_id,0)
        if component_rank == 0:
            raise RuntimeError(f'unknown component_rank for component_id: {component_id!r}')

        scons_suffix = _VSWHERE_COMPONENTID_SCONS_SUFFIX[component_id]

        if scons_suffix:
            vc_version_scons = vc_version + scons_suffix
        else:
            vc_version_scons = vc_version

        is_prerelease = True if instance.get('isPrerelease', False) else False
        is_release = False if is_prerelease else True

        msvc_instance = MSVCInstance(
            vc_path = vc_path,
            vc_version = vc_version,
            vc_version_numeric = float(vc_version),
            vc_version_scons = vc_version_scons,
            vc_release = is_release,
            vc_component_id = component_id,
            vc_component_rank = component_rank,
            vc_component_suffix = component_suffix,
        )

        msvc_instances.append(msvc_instance)

    msvc_instances = sorted(
        msvc_instances,
        key=cmp_to_key(MSVCInstance.msvc_instances_default_order)
    )

    msvc_map = {}
    for msvc_instance in msvc_instances:

        logging.debug(
            'msvc instance: msvc_version=%r, is_release=%s, component_id=%r, vc_path=%r',
            msvc_instance.vc_version_scons, msvc_instance.vc_release,
            msvc_instance.vc_component_id, msvc_instance.vc_path
        )

        key = (msvc_instance.vc_version_scons, msvc_instance.vc_release)
        msvc_map.setdefault(key,[]).append(msvc_instance)

        if msvc_instance.vc_version_scons == msvc_instance.vc_version:
            continue

        key = (msvc_instance.vc_version, msvc_instance.vc_release)
        msvc_map.setdefault(key,[]).append(msvc_instance)

    logging.info("n_msvc_instances=%d", len(msvc_instances))
    return msvc_instances, msvc_map

def find_vc_pdir(msvc_version, msvc_map):

    logging.debug("")

    is_release = True
    key = (msvc_version, is_release)

    msvc_instances = msvc_map.get(key, UNDEFINED)
    if msvc_instances == UNDEFINED:
        logging.debug(
            'msvc instances lookup failed: msvc_version=%r, is_release=%r',
            msvc_version, is_release
        )
        msvc_instances = []

    pdir = None
    for msvc_instance in msvc_instances:
        pdir = msvc_instance.vc_path
        break

    logging.info("msvc_version=%r, pdir=%r", msvc_version, pdir)
    return pdir

_ARCH_TO_CANONICAL = {
    "amd64"     : "amd64",
    "emt64"     : "amd64",
    "i386"      : "x86",
    "i486"      : "x86",
    "i586"      : "x86",
    "i686"      : "x86",
    "ia64"      : "ia64",      # deprecated
    "itanium"   : "ia64",      # deprecated
    "x86"       : "x86",
    "x86_64"    : "amd64",
    "arm"       : "arm",
    "arm64"     : "arm64",
    "aarch64"   : "arm64",
}

def arch_canonical(arch):

    logging.debug("")

    arch = arch.lower()

    try:
        host =_ARCH_TO_CANONICAL[arch]
    except KeyError:
        msg = "Unrecognized host architecture %s"
        raise RuntimeError(msg % repr(host_platform)) from None

    logging.debug("arch=%r", arch)
    return arch

def get_native_host_platform():

    logging.debug("")

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
            arch, _ = winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")
    except FileNotFoundError:
        arch = None

    if not arch:
        arch = platform.machine()

    native_host_platform = arch_canonical(arch)
    logging.debug("native_host_platform=%r", native_host_platform)

    return native_host_platform

# 14.3 (VS2022) and later

_GE2022_HOST_TARGET_BATCHFILE_CLPATHCOMPS = {

    ('amd64', 'amd64') : ('vcvars64.bat',          ('bin', 'Hostx64', 'x64')),
    ('amd64', 'x86')   : ('vcvarsamd64_x86.bat',   ('bin', 'Hostx64', 'x86')),
    ('amd64', 'arm')   : ('vcvarsamd64_arm.bat',   ('bin', 'Hostx64', 'arm')),
    ('amd64', 'arm64') : ('vcvarsamd64_arm64.bat', ('bin', 'Hostx64', 'arm64')),

    ('x86',   'amd64') : ('vcvarsx86_amd64.bat',   ('bin', 'Hostx86', 'x64')),
    ('x86',   'x86')   : ('vcvars32.bat',          ('bin', 'Hostx86', 'x86')),
    ('x86',   'arm')   : ('vcvarsx86_arm.bat',     ('bin', 'Hostx86', 'arm')),
    ('x86',   'arm64') : ('vcvarsx86_arm64.bat',   ('bin', 'Hostx86', 'arm64')),

    ('arm64', 'amd64') : ('vcvarsarm64_amd64.bat', ('bin', 'Hostarm64', 'arm64_amd64')),
    ('arm64', 'x86')   : ('vcvarsarm64_x86.bat',   ('bin', 'Hostarm64', 'arm64_x86')),
    ('arm64', 'arm')   : ('vcvarsarm64_arm.bat',   ('bin', 'Hostarm64', 'arm64_arm')),
    ('arm64', 'arm64') : ('vcvarsarm64.bat',       ('bin', 'Hostarm64', 'arm64')),

}

_GE2022_HOST_TARGET_CFG = {

    'host_all_hosts': {
        'amd64': ['amd64', 'x86'],
        'x86':   ['x86'],
        'arm64': ['arm64', 'amd64', 'x86'],
    },

    'host_def_targets': {
        'amd64': ['amd64', 'x86'],
        'x86':   ['x86'],
        'arm64': ['arm64', 'amd64', 'arm', 'x86'],
        'arm':   ['arm'],
    },

}

# 14.2 (VS2019) to 14.1 (VS2017)

_LE2019_HOST_TARGET_BATCHFILE_CLPATHCOMPS = {

    ('amd64', 'amd64') : ('vcvars64.bat',          ('bin', 'Hostx64', 'x64')),
    ('amd64', 'x86')   : ('vcvarsamd64_x86.bat',   ('bin', 'Hostx64', 'x86')),
    ('amd64', 'arm')   : ('vcvarsamd64_arm.bat',   ('bin', 'Hostx64', 'arm')),
    ('amd64', 'arm64') : ('vcvarsamd64_arm64.bat', ('bin', 'Hostx64', 'arm64')),

    ('x86',   'amd64') : ('vcvarsx86_amd64.bat',   ('bin', 'Hostx86', 'x64')),
    ('x86',   'x86')   : ('vcvars32.bat',          ('bin', 'Hostx86', 'x86')),
    ('x86',   'arm')   : ('vcvarsx86_arm.bat',     ('bin', 'Hostx86', 'arm')),
    ('x86',   'arm64') : ('vcvarsx86_arm64.bat',   ('bin', 'Hostx86', 'arm64')),

    ('arm64', 'amd64') : ('vcvars64.bat',          ('bin', 'Hostx64', 'x64')),
    ('arm64', 'x86')   : ('vcvarsamd64_x86.bat',   ('bin', 'Hostx64', 'x86')),
    ('arm64', 'arm')   : ('vcvarsamd64_arm.bat',   ('bin', 'Hostx64', 'arm')),
    ('arm64', 'arm64') : ('vcvarsamd64_arm64.bat', ('bin', 'Hostx64', 'arm64')),

}

_LE2019_HOST_TARGET_CFG = {

    'host_all_hosts': {
        'amd64': ['amd64', 'x86'],
        'x86':   ['x86'],
        'arm64': ['amd64', 'x86'],
        'arm':   ['x86'],
    },

    'host_def_targets': {
        'amd64': ['amd64', 'x86'],
        'x86':   ['x86'],
        'arm64': ['arm64', 'amd64', 'arm', 'x86'],
        'arm':   ['arm'],
    },

}

def get_msvc_version_numeric(msvc_version):
    return ''.join([x for x in msvc_version if x in string.digits + '.'])

def get_host_target(msvc_version):

    logging.debug("")

    vernum = float(get_msvc_version_numeric(msvc_version))
    vernum_int = int(vernum * 10)

    if vernum_int >= 143:
        # 14.3 (VS2022) and later
        host_target_cfg = _GE2022_HOST_TARGET_CFG
    elif 143 > vernum_int >= 141:
        # 14.2 (VS2019) to 14.1 (VS2017)
        host_target_cfg = _LE2019_HOST_TARGET_CFG
    else:
        host_target_cfg = None

    host_platform = get_native_host_platform()
    target_platform = None

    host_list = host_target_cfg['host_all_hosts'][host_platform]
    host_targets_map = host_target_cfg['host_def_targets']

    host_target_list = []

    for host_arch in host_list:

        try:
            target_list = host_targets_map[host_arch]
        except KeyError:
            msg = "Unrecognized host architecture %s for version %s"
            raise RuntimeError(msg % (repr(host_arch), msvc_version)) from None

        for target_arch in target_list:
            t = (host_arch, target_arch)
            host_target_list.append(t)

    logging.debug(
        "msvc_version=%r, host_platform=%r, target_platform=%r, host_target_list=%r",
        msvc_version, host_platform, target_platform, host_target_list
    )

    return host_platform, target_platform, host_target_list

_CL_EXE_NAME = 'cl.exe'

_VC_TOOLS_VERSION_FILE_PATH = ['Auxiliary', 'Build', 'Microsoft.VCToolsVersion.default.txt']
_VC_TOOLS_VERSION_FILE = os.sep.join(_VC_TOOLS_VERSION_FILE_PATH)

def _check_files_exist_in_vc_dir(vc_dir, msvc_version):

    logging.debug("")
    host_target_list = None

    vernum = float(get_msvc_version_numeric(msvc_version))
    vernum_int = int(vernum * 10)

    host_platform, target_platform, host_target_list = get_host_target(msvc_version)

    if vernum_int >= 141:
        # 14.1 (VS2017) and later

        default_toolset_file = os.path.join(vc_dir, _VC_TOOLS_VERSION_FILE)
        try:
            with open(default_toolset_file) as f:
                vc_specific_version = f.readlines()[0].strip()
        except OSError:
            logging.warning('failed to read %s', default_toolset_file)
            return host_target_list
        except IndexError:
            logging.warning('failed to find MSVC version in %s', default_toolset_file)
            return host_target_list

        if vernum_int >= 143:
            # 14.3 (VS2022) and later
            host_target_batchfile_clpathcomps = _GE2022_HOST_TARGET_BATCHFILE_CLPATHCOMPS
        else:
            # 14.2 (VS2019) to 14.1 (VS2017)
            host_target_batchfile_clpathcomps = _LE2019_HOST_TARGET_BATCHFILE_CLPATHCOMPS

        for host_platform, target_platform in host_target_list:

            logging.debug('host platform=%s, target platform=%s, version=%s', host_platform, target_platform, msvc_version)

            batchfile_clpathcomps = host_target_batchfile_clpathcomps.get((host_platform, target_platform), None)
            if batchfile_clpathcomps is None:
                logging.warning('unsupported host/target platform combo: (%s,%s)', host_platform, target_platform)
                continue

            batfile, cl_path_comps = batchfile_clpathcomps

            batfile_path = os.path.join(vc_dir, "Auxiliary", "Build", batfile)
            if not os.path.exists(batfile_path):
                logging.warning("batch file not found: %s", batfile_path)
                continue

            cl_path = os.path.join(vc_dir, 'Tools', 'MSVC', vc_specific_version, *cl_path_comps, _CL_EXE_NAME)
            if not os.path.exists(cl_path):
                logging.warning("%s not found: %s", _CL_EXE_NAME, cl_path)
                continue

            logging.debug('%s found: %s', _CL_EXE_NAME, cl_path)
            return host_target_list

    # version not supported return false
    logging.warning('unsupported MSVC version: %s', str(vernum))

    return host_target_list

_ENV = [
    # Platform/win32
    'SystemDrive',
    'SystemRoot',
    'TEMP',
    'TMP',
    'USERPROFILE',
    # SCons/Tool/MSCommon/common
    'ComSpec',
    'OS',
    'VSCMD_DEBUG',
    'VSCMD_SKIP_SENDTELEMETRY',
    'windir',
]

def scons_environment():
    logging.debug("")

    env = {}
    for var in _ENV:
        val = os.environ.get(var)
        if not val:
            continue
        env[var] = val

    sys32_dir = os.path.join(env['SystemRoot'], 'System32')
    sys32_wbem_dir = os.path.join(sys32_dir, 'Wbem')
    sys32_ps_dir = os.path.join(sys32_dir, 'WindowsPowerShell', 'v1.0')

    env['PATH'] = os.pathsep.join([sys32_dir, sys32_wbem_dir, sys32_ps_dir])
    env['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'

    logging.debug("env=%r", env)
    return env

re_script_output_error = re.compile(
    r'^(' + r'|'.join([
        r'VSINSTALLDIR variable is not set',             # 2002-2003
        r'The specified configuration type is missing',  # 2005+
        r'Error in script usage',                        # 2005+
        r'ERROR\:',                                      # 2005+
        r'\!ERROR\!',                                    # 2015-2015
        r'\[ERROR\:',                                    # 2017+
        r'\[ERROR\]',                                    # 2017+
        r'Syntax\:',                                     # 2017+
    ]) + r')'
)

def subproc_run(env, *args, **kwargs) -> subprocess.CompletedProcess:
    logging.debug("enter")

    kwargs['env'] = env
    kwargs['check'] = False

    start_time = time.time()

    try:
        cp = subprocess.run(*args, **kwargs)
    except OSError as exc:
        argline = ' '.join(*args)
        cp = subprocess.CompletedProcess(
            args=argline, returncode=1, stdout="", stderr=""
        )

    end_time = time.time()
    elapsed_time = end_time-start_time

    logging.debug("elapsed_time==%.2f", elapsed_time)
    return cp, elapsed_time

def get_output(vcbat, args=None, skip_sendtelemetry=False, force_env=None):
    logging.debug("vcbat=%r, force_env=%r", vcbat, force_env)

    if force_env:
        env = force_env
    else:
        env = scons_environment()

    for key, val in env.items():
        logging.debug('env[%s]=%s', key, val)

    if skip_sendtelemetry:
        # _force_vscmd_skip_sendtelemetry(env)
        pass

    if args:
        logging.debug("Calling '%s %s'", vcbat, args)
        cmd_str = '"%s" %s & set' % (vcbat, args)
    else:
        logging.debug("Calling '%s'", vcbat)
        cmd_str = '"%s" & set' % vcbat

    cp, elapsed_time = subproc_run(
        env, cmd_str, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    OEM = "oem"

    if cp.stdout:
        for line in cp.stdout.decode(OEM).splitlines():
            if not line.strip():
                continue
            logging.debug('stdout:%s', line)

    if cp.stderr:
        for line in cp.stderr.decode(OEM).splitlines():
            if not line.strip():
                continue
            logging.info('stderr:%s', line)

    # logging.debug('stdout:%s', cp.stdout)
    # logging.debug('stderr:%s', cp.stderr)

    if cp.stderr:
        sys.stderr.write(cp.stderr.decode(OEM))
    if cp.returncode != 0:
        raise OSError(cp.stderr.decode(OEM))

    logging.debug("exit")
    return cp.stdout.decode(OEM), elapsed_time

KEEPLIST = (
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "PATH",
    "VSCMD_ARG_app_plat",
    "VCINSTALLDIR",  # needed by clang -VS 2017 and newer
    "VCToolsInstallDir",  # needed by clang - VS 2015 and older
    "VSCMD_SKIP_SENDTELEMETRY",  # JCB: need to add to SCons?
)

def parse_output(output, keep=KEEPLIST):
    logging.debug("")

    # dkeep is a dict associating key: path_list, where key is one item from
    # keep, and path_list the associated list of paths
    dkeep = {i: [] for i in keep}

    # rdk will  keep the regex to match the .bat file output line starts
    rdk = {}
    for i in keep:
        rdk[i] = re.compile(r'%s=(.*)' % i, re.I)

    def add_env(rmatch, key, dkeep=dkeep) -> None:
        path_list = rmatch.group(1).split(os.pathsep)
        for path in path_list:
            # Do not add empty paths (when a var ends with ;)
            if path:
                # XXX: For some reason, VC98 .bat file adds "" around the PATH
                # values, and it screws up the environment later, so we strip
                # it.
                path = path.strip('"')
                dkeep[key].append(str(path))

    for line in output.splitlines():
        for k, value in rdk.items():
            match = value.match(line)
            if match:
                add_env(match, k)

    for key, val in dkeep.items():
        logging.debug("dkeep[%r]=%r", key, val)

    return dkeep

class BatchFileExecutionError(Exception):
    pass

def _check_cl_exists_in_script_env(data):
    logging.debug("")
    cl_path = None
    if data and 'PATH' in data:
        for p in data['PATH']:
            cl_exe = os.path.join(p, _CL_EXE_NAME)
            if os.path.exists(cl_exe):
                cl_path = cl_exe
                break
    have_cl = True if cl_path else False
    logging.debug('have_cl=%r, cl_path=%r', have_cl, cl_path)
    return have_cl, cl_path

def script_env(script, args=None, force_env=None):
    logging.debug("enter")

    # skip_sendtelemetry = _skip_sendtelemetry(env)

    skip_sendtelemetry = False
    stdout, elapsed_time = get_output(script, args, skip_sendtelemetry=skip_sendtelemetry, force_env=force_env)

    data = parse_output(stdout)

    # logging.debug(stdout)
    olines = stdout.splitlines()

    # process stdout: batch file errors (not necessarily first line)
    script_errlog = []
    for line in olines:
        if re_script_output_error.match(line):
            if not script_errlog:
                script_errlog.append('vc script errors detected:')
            script_errlog.append(line)

    if script_errlog:
        script_errmsg = '\n'.join(script_errlog)

        have_cl, _ = _check_cl_exists_in_script_env(data)

        logging.debug(
            'script=%s args=%s have_cl=%s, errors=%s',
            repr(script), repr(args), repr(have_cl), script_errmsg
        )

        if not have_cl:
            # detected errors, cl.exe not on path
            raise BatchFileExecutionError(script_errmsg)

    logging.debug("leave")
    return data, elapsed_time

def find_batch_file(msvc_version, host_arch, target_arch, pdir):
    logging.debug("")

    vernum = float(get_msvc_version_numeric(msvc_version))
    vernum_int = int(vernum * 10)

    if vernum_int >= 143:
        # 14.3 (VS2022) and later
        batfiledir = os.path.join(pdir, "Auxiliary", "Build")
        batfile, _ = _GE2022_HOST_TARGET_BATCHFILE_CLPATHCOMPS[(host_arch, target_arch)]
        batfilename = os.path.join(batfiledir, batfile)
    elif 143 > vernum_int >= 141:
        # 14.2 (VS2019) to 14.1 (VS2017)
        batfiledir = os.path.join(pdir, "Auxiliary", "Build")
        batfile, _ = _LE2019_HOST_TARGET_BATCHFILE_CLPATHCOMPS[(host_arch, target_arch)]
        batfilename = os.path.join(batfiledir, batfile)
    else:
        batfilename = ""

    if not os.path.exists(batfilename):
        logging.debug("batch file not found: %s", batfilename)
        batfilename = None

    logging.debug("batfilename=%r", batfilename)
    return batfilename

def msvc_find_valid_batch_script(vc_installed, force_env=None):
    logging.debug("enter")

    data = None
    if vc_installed:
        for host_arch, target_arch, in vc_installed.host_target_list:
            vc_script = find_batch_file(vc_installed.vc_version, host_arch, target_arch, vc_installed.vc_dir)
            if not vc_script:
                continue
            arg = ""
            logging.debug('trying vc_script=%r, vc_script_args=%s', vc_script, arg)
            try:
                data, elapsed_time = script_env(vc_script, args=arg, force_env=force_env)
            except BatchFileExecutionError as e:
                logging.debug('failed vc_script=%r, vc_script_args=%s, error=%s', vc_script, arg, e)
                vc_script = None
                continue
            logging.info("ELAPSED_TIME=%.2f, vc_script=%r", elapsed_time, vc_script)
            have_cl, _ = _check_cl_exists_in_script_env(data)
            if not have_cl:
                logging.debug('skip cl.exe not found vc_script=%r, vc_script_args=%s', vc_script, arg)
                continue
            logging.debug("Found a working script/target: %r/%s", vc_script, arg)
            d = {}
            d['MSVC_VERSION'] = vc_installed.vc_version
            d['HOST_ARCH'] = host_arch
            d['TARGET_ARCH'] = target_arch
            d.update(data)
            data = d
            break

    if data:
        for key, val in data.items():
            logging.debug("data[%r]=%r", key, val)
    else:
        logging.debug("data=%r", data)

    return data

_MSVCInstalled = namedtuple('_MSVCInstalled', [
    'vc_version',
    'vc_dir',
    'host_target_list',
])

_VCVER = [
    "14.3",
    "14.2",
    "14.1", "14.1Exp",
]

def get_installed_vcs(msvc_map):

    logging.debug("")

    installed_versions = []

    for ver in _VCVER:
        VC_DIR = find_vc_pdir(ver, msvc_map)
        if VC_DIR:
            logging.debug('found VC %s', ver)
            host_target_list = _check_files_exist_in_vc_dir(VC_DIR, ver)
            if host_target_list:
                vc_installed = _MSVCInstalled(
                    vc_version=ver,
                    vc_dir=VC_DIR,
                    host_target_list=tuple(host_target_list),
                )
                installed_versions.append(vc_installed)
                logging.debug(
                    'installed version: msvc_version=%r, vc_dir=%r, host_target_list=%r',
                    vc_installed.vc_version, vc_installed.vc_dir, vc_installed.host_target_list,
                )
            else:
                logging.debug('no compiler found %s', ver)
        else:
            logging.debug('not found VC %s', ver)

    logging.info("n_installed_versions = %d", len(installed_versions))
    return installed_versions

### SCons Modified Source Code End

# Windows runner PSModulePath
#
# runner 1:
#     C:\\Modules\az_12.4.0
#     C:\Users\packer\Documents\WindowsPowerShell\Modules
#     C:\Program Files\WindowsPowerShell\Modules
#     C:\Windows\system32\WindowsPowerShell\v1.0\Modules
#     C:\Program Files\Microsoft SQL Server\130\Tools\PowerShell\Modules\
#
# runner 2:
#     C:\Users\runneradmin\Documents\PowerShell\Modules
#     C:\Program Files\PowerShell\Modules
#     c:\program files\powershell\7\Modules
#     C:\\Modules\az_12.4.0
#     C:\Users\packer\Documents\WindowsPowerShell\Modules
#     C:\Program Files\WindowsPowerShell\Modules
#     C:\Windows\system32\WindowsPowerShell\v1.0\Modules
#     C:\Program Files\Microsoft SQL Server\130\Tools\PowerShell\Modules\

#
# vcpkg_root = os.environ.get("VCPKG_ROOT")
# if vcpkg_root:
#     vcpkg_root_exists = os.path.exists(vcpkg_root)
# else:
#     vcpkg_root_exists = False

# vcpkg_installation_root = os.environ.get("VCPKG_INSTALLATION_ROOT")
# if vcpkg_installation_root:
#     vcpkg_installation_root_exists = os.path.exists(vcpkg_installation_root)
# else:
#     vcpkg_installation_root_exists = False

# * check of .vcpg-root?
# * check USERPROFILE if can't find VC_ROOT?

#if vcpkg_installation_root_exists:
#    env["VCPKG_INSTALLATION_ROOT"] = vcpkg_installation_root

#if vcpkg_root_exists:
#    env["VCPKG_ROOT"] = vcpkg_root
#elif vcpkg_installation_root_exists:
#    env["VCPKG_ROOT"] = vcpkg_installation_root

_TEST_ENV = [
    'VCPKG_DISABLE_METRICS',  # TODO(JCB): NEW
    'VCPKG_ROOT',  # TODO(JCB): NEW
]

def test_environment():
    logging.debug("")

    env = {}
    for var in _ENV + _TEST_ENV:
        val = os.environ.get(var)
        if not val:
            continue
        env[var] = val

    sys32_dir = os.path.join(env['SystemRoot'], 'System32')
    sys32_wbem_dir = os.path.join(sys32_dir, 'Wbem')
    progfiles_ps_dir = os.path.expandvars("%ProgramFiles%\\PowerShell\\7")
    sys32_ps_dir = os.path.join(sys32_dir, 'WindowsPowerShell', 'v1.0')

    syspath_dirs = [
        sys32_dir,
        sys32_wbem_dir,
        progfiles_ps_dir,  # TODO(JCB): NEW
        sys32_ps_dir,
    ]

    env['PATH'] = os.pathsep.join(syspath_dirs)
    env['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'

    psmodpath_dirs = [
        os.path.expandvars("%ProgramFiles%\\PowerShell\\Modules"),
        os.path.expandvars("%ProgramFiles%\\PowerShell\\7\\Modules"),
        os.path.expandvars("%ProgramFiles%\\WindowsPowerShell\\Modules"),
        os.path.expandvars("%windir%\\System32\\WindowsPowerShell\\v1.0\\Modules"),
    ]

    env["PSModulePath"] = os.pathsep.join(psmodpath_dirs)  # TODO(JCB): NEW

    logging.debug("env=%r", env)
    return env

_DEV_ENV = [
    'VCPKG_DISABLE_METRICS',  # TODO(JCB): NEW
    # 'VCPKG_ROOT',  # TODO(JCB): NEW
]

def dev_environment():
    logging.debug("")

    env = {}
    for var in _ENV + _DEV_ENV:
        val = os.environ.get(var)
        if not val:
            continue
        env[var] = val

    sys32_dir = os.path.join(env['SystemRoot'], 'System32')
    sys32_wbem_dir = os.path.join(sys32_dir, 'Wbem')
    progfiles_ps_dir = os.path.expandvars("%ProgramFiles%\\PowerShell\\7")
    sys32_ps_dir = os.path.join(sys32_dir, 'WindowsPowerShell', 'v1.0')

    syspath_dirs = [
        sys32_dir,
        sys32_wbem_dir,
        progfiles_ps_dir,
        sys32_ps_dir,
    ]

    env['PATH'] = os.pathsep.join(syspath_dirs)
    env['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'

    psmodpath_dirs = [
        os.path.expandvars("%ProgramFiles%\\PowerShell\\Modules"),
        os.path.expandvars("%ProgramFiles%\\PowerShell\\7\\Modules"),
        os.path.expandvars("%ProgramFiles%\\WindowsPowerShell\\Modules"),
        os.path.expandvars("%windir%\\System32\\WindowsPowerShell\\v1.0\\Modules"),
    ]

    env["PSModulePath"] = os.pathsep.join(psmodpath_dirs)

    logging.debug("env=%r", env)
    return env

def log_environ():
    for key, val in os.environ.items():
        logging.info("os.environ[%s]=%s", key, val)

def log_syspath_programs(proglist):
    logging.debug("")
    syspath_locations = {}
    syspath = os.environ.get("PATH")
    if syspath:
        for p in syspath.split(os.pathsep):
            for progname in proglist:
                progpath = os.path.join(os.path.normpath(p), progname)
                if not os.path.exists(progpath):
                    continue
                syspath_locations.setdefault(progname, []).append(progpath)
                logging.info("progname=%r, progpath=%r", progname, progpath)
    logging.debug("")
    return syspath_locations

def msvc_default_version():
    logging.debug("")
    log_syspath_programs(["vcpkg.exe", "pwsh.exe", "powershell.exe"])
    log_environ()
    vswhere_exe = vswhere_executable()
    vswhere_json = vswhere_query_json_output(vswhere_exe, ['-all', '-products', '*'])
    msvc_instances, msvc_map = vswhere_msvc_instances(vswhere_json)
    installed_versions = get_installed_vcs(msvc_map)
    default_version = installed_versions[0] if installed_versions else None
    logging.info("default_version=%r", default_version)
    return default_version

def test_ext_scripts(vc_installed):
    logging.debug("")
    if TEST_NEWENV:
        env_list = [("test", test_environment())]
    else:
        env_list = [("scons", scons_environment())]
    vs_root = os.path.split(vc_installed.vc_dir)[0]
    vs_tools = os.path.join(vs_root, "Common7", "Tools")
    vs_vsdevcmd = os.path.join(vs_tools, "vsdevcmd")
    vs_vsdevcmd_core = os.path.join(vs_vsdevcmd, "core")
    vs_vsdevcmd_ext = os.path.join(vs_vsdevcmd, "ext")
    vsdevcmd_ext_files = [
        p for p in 
        [os.path.join(vs_vsdevcmd_ext, p) for p in os.listdir(vs_vsdevcmd_ext)]
        if os.path.isfile(p) and os.path.splitext(p)[-1].lower() == ".bat"
    ]
    vsdevcmd_ext_files.sort()
    vsdevcmd_env = {
        "DevEnvDir": os.path.join(vs_root, "Common7", "IDE") + "\\",
        "VCIDEINSTALLDIR": os.path.join(vs_root, "Common7", "IDE", "VC") + "\\",
        "VCINSTALLDIR": os.path.join(vs_root, "VC") + "\\",
        "VSINSTALLDIR": vs_root + "\\",
        # JCB: TODO REMOVE HARDCODED
        "VSCMD_ARG_app_plat": "Desktop",
        "VSCMD_ARG_HOST_ARCH": "x64",
        "VSCMD_ARG_TGT_ARCH": "x64",
        "VSCMD_SKIP_SENDTELEMETRY": "1",
        "VSCMD_VER": "17.0",
    }
    for label, baseenv in env_list:
        env = dict(baseenv)
        for key, val in vsdevcmd_env.items():
            if key in env:
                continue
            env[key] = val
        for key, val in env.items():
            logging.info('env[%s]=%s', key, val)
        for batfile in vsdevcmd_ext_files:
            filename = os.path.split(batfile)[-1]
            if filename.lower() in ("vcvars.bat",):
                continue
            for call_num in range(_EXT_ITERATIONS):
                data, elapsed_time = script_env(batfile, force_env=env)
                if elapsed_time > _EXT_ELAPSED_TOLERANCE:
                    logging.warning("!!! ELAPSED_TIME=%.2f, envkind=%s, script=%r !!!", elapsed_time, label, batfile)
                else:
                    logging.info("ELAPSED_TIME=%.2f, envkind=%s, callnum=%d, script=%r", elapsed_time, label, call_num, batfile)
    logging.debug("")

def test_scons(vc_installed):
    logging.debug("")
    if TEST_DEVENV:
        env = dev_environment()
    elif TEST_NEWENV:
        env = test_environment()
    else:
        env = scons_environment()
    for key, val in env.items():
        logging.info('env[%s]=%s', key, val)
    for call_num in range(_SCONS_ITERATIONS):
        _ = msvc_find_valid_batch_script(vc_installed, force_env=env)
    logging.debug("")

def msvc_default_invocation(func_list):
    logging.debug("")
    default_version = msvc_default_version()
    if default_version and func_list:
        for func in func_list:
            if not func:
                continue
            func(default_version)
    logging.debug("")

func_list = [test_scons] if TEST_VCVARS else [test_ext_scripts]

msvc_default_invocation(func_list)
logging.info("finished")

