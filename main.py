#!C:\Python27\python.exe

import os
import sys
from re import match, sub, split
import zipfile
import os.path
import msvcrt
import traceback
import cgi


reload(sys)
sys.setdefaultencoding('utf-8')

from jinja2 import Environment, FileSystemLoader

sys.stderr = sys.stdout


class Parsers:
    @staticmethod
    def get_value(value=str, line=str):
        m = match('^.*%s[ ]*:' % value, line)
        line = line[:-1] if line[-1:] == "\n" else line
        if m is not None:
            return sub("^.*?:[ ]*", "", line)
        else:
            return None

    @staticmethod
    def len(item):
        return len(item)


class Policies(Parsers):
    def __init__(self, bppllist):
        self.policies = dict()
        self.__pdefaults__ = [("Options", "0x0"), ("template", "FALSE"), ("audit_reason", "?"), ("Names", "(none)"),
                              ("Policy Type", None), ("Active", "yes"),
                              ("Effective date", None), ("Mult. Data Stream", "no"),
                              ("Perform Snapshot Backup", "no"), ("Snapshot Method", "(none)"),
                              ("Snapshot Method Arguments", "(none)"), ("Perform Offhost Backup", "no"),
                              ("Backup Copy", "0"), ("Use Data Mover", "no"), ("Data Mover Type", None),
                              ("Use Alternate Client", "no"), ("Alternate Client Name", "(none)"),
                              ("Use Virtual Machine", "0"), ("Hyper-V Server Name", "(none)"),
                              ("Enable Instant Recovery", "no"), ("Policy Priority", None), ("Max Jobs/Policy", None),
                              ("Disast er Recovery", "0"), ("Collect BMR Info", "no"), ("Keyword", "(none specified)"),
                              ("Data Classification", "-"), ("Residence is Storage Lifecycle Policy", None),
                              ("Client Encrypt", "no"), ("Checkpoint", "no"), ("Residence", None),
                              ("Volume Pool", None), ("Server Group", "*ANY*"), ("Granular Restore Info", "no"),
                              ("Exchange Source attributes", "no"), ("Exchange DAG Preferred Server", "(none defined)"),
                              ("Application Discovery", "no"), ("Discovery Lifetime", "0 seconds"),
                              ("ASC Application and attributes", "(none defined)"), ("Generation", "8"),
                              ("Ignore Client Direct", "no"), ("Enable Metadata Indexing", "no"),
                              ("Index server name", "NULL"), ("Use Accelerator", "no")]
        self.__sdefaults__ = [("  Type", None), ("  Retention Level", None), ("  u-wind/o/d", "0 0"),
                              ("  Incr Type", None),
                              ("  Alt Read Host", "(none defined)"), ("  Max Frag Size", "0 MB"), ("  Synthetic", "0"),
                              ("  Checksum Change Detection", "0"), ("  PFI Recovery", "0"), ("  Maximum MPX", "10"),
                              ("  Number Copies", "1"), ("  Fail on Error", "0"), ("  Residence", None),
                              ("  Volume Pool", "(same as policy volume pool)"),
                              ("  Server Group", "(same as specified for policy)"),
                              ("  Residence is Storage Lifecycle Policy", "0"), ("  Schedule indexing", "0")]
        self._generate(bppllist)

    def __getitem__(self, item):
        if item in self.policies:
            return self.policies[item]
        else:
            return None

    def __iter__(self):
        if self.policies:
            for policy in self.policies:
                yield policy
        else:
            yield None

    def _generate(self, bppllist):
        f = None
        policy = None
        schedule = None
        for line in bppllist:
            if self.get_value("Policy Name", line) is not None:
                policy = self.get_value("Policy Name", line)
                self.policies[policy] = dict()
                self.policies[policy]["attributes"] = dict()
                self.policies[policy]["schedules"] = dict()
                self.policies[policy]["selection"] = list()
                self.policies[policy]["clients"] = list()
            if policy is not None:
                for (attr, _) in self.__pdefaults__:
                    val = self.get_value(attr, line)
                    if val is not None:
                        if (attr, val) in self.__pdefaults__:
                            continue
                        else:
                            self.policies[policy]["attributes"][attr] = val
                if self.get_value("Snapshot Method Arguments", line) is not None:
                    s = split(",", self.get_value("Snapshot Method Arguments", line))
                    val = ""
                    for i in s:
                        val += i + "<br>\n"
                    self.policies[policy]["attributes"]["Snapshot Method Arguments"] = val
                if self.get_value("Include", line) is not None:
                    self.policies[policy]["selection"].append(self.get_value("Include", line))
                if line[:7] == "Client/":
                    m = split("[ ]+", sub(".*:[ ]+", "", line))
                    client_name = m[0]
                    clint_os = m[2]
                    self.policies[policy]["clients"].append((client_name, clint_os))
                if self.get_value("Schedule", line) is not None:
                    schedule = self.get_value("Schedule", line)
                    self.policies[policy]["schedules"][schedule] = dict()
                    self.policies[policy]["schedules"][schedule]["Calendar schedule"] = None
                    self.policies[policy]["schedules"][schedule]["Attributes"] = dict()
                    self.policies[policy]["schedules"][schedule]["Windows"] = list()
                    f = None
                if line[:2] == "  ":
                    for (attr, _) in self.__sdefaults__:
                        val = self.get_value(attr, line)
                        if val is not None:
                            if (attr, val) in self.__sdefaults__:
                                continue
                            else:
                                attr = attr[2:]
                                self.policies[policy]["schedules"][schedule]["Attributes"][attr] = val
                if self.get_value("  Calendar sched", line) == "Enabled":
                    self.policies[policy]["schedules"][schedule]["Calendar schedule"] = dict()
                    self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Included dates"] = list()
                    self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Excluded dates"] = list()
                    f = "Include"
                if line[:28] == "   Included Dates-----------":
                    f = "Include"
                if line[:27] == "   Excluded Dates----------":
                    f = "Exclude"
                if line[:4] == "    ":
                    if schedule in self.policies[policy]["schedules"]:
                        if self.policies[policy]["schedules"][schedule]["Calendar schedule"] is None:
                            self.policies[policy]["schedules"][schedule]["Calendar schedule"] = dict()
                            self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Included dates"] = list()
                            self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Excluded dates"] = list()
                            f = "Include"
                    if line[:17] == "    SPECIFIC DATE":
                        date = sub(".*\- ", "", line)
                        self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Included dates"].append(date)
                    elif line[:16] == "    EXCLUDE DATE":
                        date = sub(".*\- ", "", line)
                        self.policies[policy]["schedules"][schedule]["Calendar schedule"]["Excluded dates"].append(date)
                    else:
                        if line.find("No") == -1 and line.find("Interval") == -1:
                            date = sub("^[ ]+", "", line)
                            if f == "Include":
                                self.policies[policy]["schedules"][schedule]["Calendar schedule"][
                                    "Included dates"].append(date)
                            elif f == "Exclude":
                                self.policies[policy]["schedules"][schedule]["Calendar schedule"][
                                    "Excluded dates"].append(date)
                if line[:9] in ["   Sunday", "   Monday", "   Tuesda", "   Wednes", "   Thursd", "   Friday",
                                "   Saturd"]:
                    self.policies[policy]["schedules"][schedule]["Windows"].append(split("[ ]+", line)[1:4])

    def print_dates(self, policy, schedule, p_type):
        output = ""
        if policy in self.policies:
            if schedule in self[policy]["schedules"]:
                for date in self[policy]["schedules"][schedule]["Calendar schedule"][p_type]:
                    output += date + " \n"
                    output = sub(" ", "&nbsp", output)
                return output
            else:
                return None
        else:
            return None

    def draw_windows(self, policy, schedule):
        seconds = dict()
        output = ""
        coordinates = list()
        days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
        if policy in self.policies:
            if schedule in self[policy]["schedules"]:
                for (day, begin, end) in self.policies[policy]["schedules"][schedule]["Windows"]:
                    _begin = split(":", begin)
                    _end = split(":", end)
                    s_begin = int(_begin[0]) * 60 * 60 + int(_begin[1]) * 60 + int(_begin[2])
                    s_end = int(_end[0]) * 60 * 60 + int(_end[1]) * 60 + int(_end[2])
                    seconds[day] = (s_begin, s_end)
        for day in days:
            coordinates.append([-1, -1, seconds[day][0], seconds[day][1]])
        for x in range(0, 7):
            for i in range(0, 7):
                if coordinates[i][3] > 24 * 60 * 60:
                    delta = coordinates[i][3] - 24 * 60 * 60
                    if i < 6:
                        coordinates[i + 1][1] = delta
                        coordinates[i + 1][0] = 0
                    else:
                        coordinates[0][1] = delta
                        coordinates[0][0] = 0
                    coordinates[i][3] = 24 * 60 * 60
                if coordinates[i][1] > 24 * 60 * 60:
                    delta = coordinates[i][1] - 24 * 60 * 60
                    if i < 6:
                        coordinates[i + 1][1] = delta
                        coordinates[i + 1][0] = 0
                    else:
                        coordinates[0][1] = delta
                        coordinates[0][0] = 0
                    coordinates[i][1] = 24 * 60 * 60
        for i in range(0, 7):
            output += "<tr>\n"
            output += "<td style='border-left:padding:0; 0;border-top:0;border-bottom:0;'>" + days[i] + "</td>\n"
            if coordinates[i][0] >= 0:
                output += "<td style='border-top:0;padding:0; border-bottom:0;'><div style='position:relative;background-color: rgb(230, 91, 1);width:" + str(
                    round(333 * (coordinates[i][1] - coordinates[i][0]) / (
                        24 * 60 * 60)) + round(coordinates[i][1] / (24 * 60 * 60) * 1.25)) + "pt;'>&nbsp</div></td>\n"
                if coordinates[i][3] != 0:
                    for j in range(1, 12):
                        if j * 20 < round(240 * coordinates[i][2] / (24 * 60 * 60)) and round(
                                                240 * coordinates[i][2] / (24 * 60 * 60)) < (j + 1) * 20:
                            output += "<td style='border-top:0;padding:0; border-bottom:0;'><div style='position:relative;background-color: rgb(230, 91, 1);margin-left:" + str(
                                round((240 * coordinates[i][2] / (
                                    24 * 60 * 60)) - j * 20) * 1.25) + "pt;width: " + str(round(
                                321 * (coordinates[i][3] - coordinates[i][2]) / (
                                    24 * 60 * 60)) + (12 - j) * 1.25) + "pt;'>&nbsp</div></td>\n"
                        else:
                            output += "<td style='border-top:0;padding:0; border-bottom:0;'></td>\n"
                else:
                    for j in range(1, 12):
                        output += "<td style='border-top:0;padding:0; border-bottom:0;'></td>\n"
            else:
                if coordinates[i][3] != 0:
                    for j in range(0, 12):
                        if j * 20 <= round(240 * coordinates[i][2] / (24 * 60 * 60)) and round(
                                                240 * coordinates[i][2] / (24 * 60 * 60)) < (j + 1) * 20:
                            output += "<td style='border-top:0;padding:0; border-bottom:0;'><div style='background-color: rgb(230, 91, 1);position: relative;margin-left:" + str(
                                round((240 * coordinates[i][2] / (
                                    24 * 60 * 60)) - j * 20) * 1.25) + "pt;width: " + str(round(
                                333 * (coordinates[i][3] - coordinates[i][2]) / (
                                    24 * 60 * 60)) + round((coordinates[i][3] - coordinates[i][2]) / (
                                24 * 60 * 60) * 1.25)) + "pt;'>&nbsp</div></td>\n"
                        else:
                            output += "<td style='border-top:0; border-bottom:0; padding:0;'></td>\n"
                else:
                    for j in range(0, 12):
                        output += "<td style='border-top:0; border-bottom:0; padding:0;'></td>\n"
        output += "</tr>"
        return output


class SLPs(Parsers):
    def __init__(self, nbstl):
        self.slp = dict()
        self._nbstl = nbstl
        self._sdefaults = [("Data Classification", "(none specified)"), ("Duplication job priority", "0"),
                           ("State", None), ("Version", "1")]
        self._odefaults = [("Storage", None), ("Volume Pool", "(none specified)"),
                           ("Server Group", "(none specified)"), ("Retention Type", "0 (Fixed)"),
                           ("Retention Level", None), ("Alternate Read Server", "(none specified)"),
                           ("Preserve Multiplexing", "false"), ("Enable Automatic Remote Import", "true"),
                           ("State", "active"), ("Source", None), ("Operation ID", "(none specified)"),
                           ("Operation Index", None)]
        self._generate()

    def __getitem__(self, item):
        return self.slp[item]

    def __iter__(self):
        if self.slp:
            for slp in self.slp:
                yield slp
        else:
            yield None

    def _generate(self):
        slp = None
        operation = None
        for line in self._nbstl:
            if self.get_value("Name", line) is not None:
                slp = self.get_value("Name", line)
                operation = None
                self.slp[slp] = dict()
                self.slp[slp]["attributes"] = list()
                self.slp[slp]["operations"] = list()
                continue
            if slp is not None:
                if operation is None:
                    for (attr, default_value) in self._sdefaults:
                        value = self.get_value(attr, line)
                        if value != default_value and value is not None:
                            self.slp[slp]["attributes"].append((attr, value))
                            continue
                if self.get_value("Use for", line) is not None:
                    operation = dict()
                    self.slp[slp]["operations"].append(operation)
                    self.slp[slp]["operations"][-1]["attributes"] = list()
                    self.slp[slp]["operations"][-1]["attributes"].append(("Type", self.get_value("Use for", line)))
                    continue
                if operation is not None:
                    for (attr, default_value) in self._odefaults:
                        value = self.get_value(attr, line)
                        if value != default_value and value is not None:
                            self.slp[slp]["operations"][-1]["attributes"].append((attr, value))
                            continue


class DiskPools(Parsers):
    def __init__(self, adv_disk):
        self.diskpools = dict()
        self._adv_disk = adv_disk
        self._pdefaults = [("Disk Pool Id", None),
                           ("Disk Type", None), ("Status", None), ("Raw Size (GB)", None), ("Usable Size (GB)", None),
                           ("Num Volumes", None), ("High Watermark", None), ("Low Watermark", None),
                           ("Max IO Streams", "-1"), ("Comment", ""), ("Storage Server", None)]
        self._generate()

    def __getitem__(self, item):
        return self.diskpools[item]

    def __iter__(self):
        if self.diskpools:
            for diskpool in self.diskpools:
                yield diskpool
        else:
            yield None

    def _generate(self):
        diskpool = None
        start_input = False
        for line in self._adv_disk:
            if not start_input:
                if line.find("-listdp -allowanydt -U") != -1:
                    start_input = True
            else:
                if self.get_value("Disk Pool Name", line) is not None:
                    diskpool = self.get_value("Disk Pool Name", line)
                    self.diskpools[diskpool] = list()
                for (attr, default_value) in self._pdefaults:
                    if self.get_value(attr, line) is not None:
                        value = self.get_value(attr, line)
                        if value != default_value:
                            self.diskpools[diskpool].append((attr, value))
                if line[:10] == "----------":
                    return 0


class devices(Parsers):
    def __init__(self, nbconfig):
        self.devices = dict()
        self.robots = dict()
        self.drives = dict()
        self._nbconfig = nbconfig
        self._rdefaults = {"Robot Number": None, "Robot Type": None,
                           "Media Server": None, "Port": None, "Bus": None, "Target": None, "Lun": None,
                           "PartiallyConfigured": "0", "Pird": "0", "Host": "-", "Apath": None,
                           "NDMP Attach Host": "-", "VMhost": None, "DAhost": None, "SN": None,
                           "Inquiry": None, "WorldWideId": None, "Old DAhost": None,
                           "RSM GUID": "00000000-0000-0000-0000-000000000000"}
        self._ddefaults = {"Index": None, "Drive Type": None,
                           "Media Server": None, "Occupy Index": "0", "Opr Count": "0", "Status": "2",
                           "Saved Mode Bits": "8624", "Access Mode": "82", "Robot Type": None, "Robot Number": None,
                           "Loc1": None, "Loc2": None, "Loc3": None, "Loc4": None, "Loc5": None, "Port": None,
                           "Bus": None, "Target": None, "Lun": None, "VH Saved Mode Bits": "0", "Flags": "128",
                           "PathFlags": "0", "DeviceFlags": "0", "Time Mounted": None, "Total Time Mounted": None,
                           "Cleaning Frequency": None, "Last Time Cleaned": None, "Vendor Device Num": "0",
                           "Tape Alert 1": "0", "Tape Alert 2": "1", "Last DA Call Time": "0", "Application Type": "0",
                           "Drive Path": None,
                           "Volume Header Drive Path": None,
                           "Vendor Drive Name": "-", "Current RVSN": "-", "Current EVSN": "-", "Current User": "-",
                           "Operator Comment": "-", "SN": None, "Inquiry Info": None,
                           "World Wide Id": "-", "NDMP Host": "-", "Scan Host": None,
                           "Assign Host": "-", "RSM GUID": "00000000-0000-0000-0000-000000000000",
                           "APPL_GUID": "00000000-0000-0000-0000-000000000000"}
        self._generate()
        self._format()

    def __getitem__(self, item):
        return self.devices[item]

    def __iter__(self):
        if self.devices:
            for device in self.devices:
                yield device
        else:
            yield None

    def _generate(self):
        start_processing = False
        robot = None
        drive = None
        for line in self.devices:
            if not start_processing:
                if line.find("-emm_dev_list") != -1:
                    start_processing = True
            else:
                if self.get_value("Robot", line) is not None:
                    robot = self.get_value("Robot", line)
                    drive = None
                    self.robots[robot] = dict()
                    self.robots[robot]["attributes"] = dict()
                    self.robots[robot]["drives"] = None
                if self.get_value("Drive", line) is not None:
                    drive = self.get_value("Drive", line)
                    robot = None
                    self.drives[drive] = dict()
                    self.drives[drive]["attributes"] = dict()
                if robot:
                    for (attr, default_value) in self._rdefaults:
                        if self.get_value(attr, line) is not None:
                            value = self.get_value(attr, line)
                            if value != default_value:
                                self.robots[robot][attr] = value
                if drive:
                    for (attr, default_value) in self._ddefaults:
                        if self.get_value(attr, line) is not None:
                            value = self.get_value(attr, line)
                            if value != default_value:
                                self.drives[drive][attr] = value
                if line.find("Master") != -1:
                    return 0

    def _format(self):
        self.devices = self.robots
        robot = None
        for drive in self.drives:
            robot_index = self.drives[drive]["attributes"]["Robot Number"]
            for robot in self.devices:
                if self.devices[robot]["attributes"]["Robot Number"] == robot_index:
                    if self.devices[robot]["drives"] is None:
                        self.devices[robot]["drives"] = list()
                        self.devices[robot]["drives"].append(drive)
                        self.drives.__delitem__(drive)
                    else:
                        self.devices[robot]["drives"].append(drive)
                        self.drives[drive]["standalone"] = False
                        del self.drives[drive]
        for drive in self.drives:
            self.device[drive]["standalone"] = True
            self.devices[drive] = self.drives








class NBSU:
    def __init__(self, path):
        self.path = path
        self.cont = dict()
        self.generalinfo = dict()
        self.masterattr = [(str, str), ]
        self.emmattr = [(str, str), ]
        self.devices = dict()
        self.stuMM = dict()
        self.stuDisk = dict()
        self.pools = dict()
        self.vpools = [(str, str), ]
        self.servers = [(str, str, str, str), ]
        ( _, _, filelist) = next(os.walk(self.path))
        f = 0
        for filename in filelist:
            if match(".*txt", filename) is not None:
                self.cont[filename] = open(self.path + "\\" + filename, 'r').readlines()
        if "nbsu_info.txt" not in self.cont:
            self.cont["nbsu_info.txt"] = "empty"
        for line in self.cont["nbsu_info.txt"]:
            if match(r"^System hostname = (.*)$", line) is not None:
                self.generalinfo["Master Server Hostname"] = match(r"^System hostname = (.*)$", line).group(1)
            if match(r"^NetBackup version = (.*)$", line) is not None:
                self.generalinfo["NetBackup Version"] = match(r"^NetBackup version = (.*)$", line).group(1)
        if "OS_general.txt" not in self.cont:
            self.cont["OS_general.txt"] = "empty"
        for line in self.cont["OS_general.txt"]:
            if match(r"^OS Name: +(.*)$", line) is not None:
                self.generalinfo["Master Server OS"] = match(r"^OS Name: +(.*)$", line).group(1)
            if match(r"^Total Physical Memory: +(.*)$", line) is not None:
                self.generalinfo["Master Server Memory"] = match(r"^Total Physical Memory: +(.*)$", line).group(1)
        if "NBU_bpconfig.txt" not in self.cont:
            self.cont["NBU_bpconfig.txt"] = "empty"
        for line in self.cont["NBU_bpconfig.txt"][4:]:
            m = match(r"^(?P<attr>.*): +(?P<value>.*)$", line)
            if m is not None:
                if m.group("attr") is None:
                    continue
                if m.group("value") is None:
                    turp = (m.group("attr"), "-")
                else:
                    turp = (m.group("attr"), m.group("value"))
                self.masterattr.append(turp)
            else:
                continue
        d = dict()
        f = 0
        if "NBU_emm_config.txt" not in self.cont:
            self.cont["NBU_emm_config.txt"] = "empty"
        for line in self.cont["NBU_emm_config.txt"]:
            if not f:
                if line[:30] == "The following hosts were found":
                    f = 1
                    continue
                else:
                    continue
            if line[:30] == "Command completed successfully":
                break
            m = match(r"^(?P<value>.*) +(?P<attr>.*)$", line)
            if m is not None:
                if m.group("attr") not in d:
                    d[m.group("attr")] = m.group("value")
                else:
                    d[m.group("attr")] = d[m.group("attr")] + "<br>" + m.group("value")
            else:
                continue
        for attr in d:
            self.emmattr.append((attr, d[attr]))
        f = 0
        f1 = 0
        for line in self.cont["NBU_emm_config.txt"]:
            if f == 0:
                if match(r".*verbose.*", line) is not None:
                    f = 1
                    continue
                else:
                    continue
            m = match(r"\s+(\w+)", line)
            if m is not None:
                attr = m.group(1)
                if attr == "MachineName":
                    if f1 == 1:
                        self.servers.append((v1, v2, v3, v4))
                    m1 = match(r".*\"(.*)\"", line)
                    v1 = m1.group(1)
                    v2 = " "
                    v3 = " "
                    v4 = " "
                    f1 = 1
                if attr == "MachineNbuType":
                    m1 = match(r".*= (\w+).*", line)
                    v2 = m1.group(1)
                if attr == "OperatingSystem":
                    m1 = match(r".*= (\w+) .*", line)
                    v3 = m1.group(1)
                if attr == "NetBackupVersion":
                    m1 = match(r".*= (.*) .*", line)
                    v4 = m1.group(1)
        self.servers.append((v1, v2, v3, v4))
        d = dict()
        f = str
        if "MM_tpconfig_emm.txt" not in self.cont:
            self.cont["MM_tpconfig_emm.txt"] = "empty"
        for line in self.cont["MM_tpconfig_emm.txt"]:
            if line[:6] == "Robot:":
                m = match(".*: +(.*)$", line)
                f = "robot"
                name = m.group(1)
                self.devices[name] = list()
                self.devices[name].append(("Robot Name", m.group(1)))
            if line[:6] == "Drive:":
                m = match(".*: +(.*)$", line)
                name = m.group(1)
                f = "drive"
                self.devices[name] = list()
                self.devices[name].append(("Drive Name", m.group(1)))
            if line[:13] == "Robot Number:" and f == "robot":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Robot Number", m.group(1)))
            if line[:11] == "Robot Type:" and f == "robot":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Robot Type", m.group(1)))
            if line[:13] == "Media Server:" and f == "robot":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Media Server", m.group(1)))
            if line[:3] == "SN:" and f == "robot":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Serial Number", m.group(1)))
            if line[:13] == "Inquiry Info:" and f == "robot":
                m = match("^Inquiry Info: +(.*)", line)
                self.devices[name].append(("Inquiry Info", m.group(1)))
                f = ""
            if line[:6] == "Index:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Index", m.group(1)))
            if line[:11] == "Drive Type:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Drive Type", m.group(1)))
            if line[:13] == "Media Server:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Media Server", m.group(1)))
            if line[:11] == "Robot Type:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Control Robot Type", m.group(1)))
            if line[:13] == "Robot Number:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Control Robot Number", m.group(1)))
            if line[:3] == "SN:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Serial Number", m.group(1)))
            if line[:13] == "Inquiry Info:" and f == "drive":
                m = match(".*: +(.*)$", line)
                self.devices[name].append(("Inquiry Info", m.group(1)))
                f = ""
        t = ""
        d = dict()
        if "NBU_adv_disk.txt" not in self.cont:
            self.cont["NBU_adv_disk.txt"] = "empty"
        for line in self.cont["NBU_adv_disk.txt"]:
            if match(".*(stype AdvancedDisk|stype BasicDisk|stype PureDisk).*", line) is not None:
                break
            m = match(".*: *(.*)", line)
            if line[:5] == "Label":
                name = m.group(1)
                d[name] = list()
                d[name].append(("Label", m.group(1)))
            if line[:17] == "Storage Unit Type":
                d[name].append(("Storage Unit Type", m.group(1)))
                if m.group(1) == "Media Manager":
                    t = "Tape"
                else:
                    t = "Disk"
            if t == "Tape":
                if line[:15] == "Host Connection":
                    d[name].append(("Host Connection", m.group(1)))
                if line[:16] == "Number of Drives":
                    d[name].append(("Number of Drives", m.group(1)))
                if line[:14] == "On Demand Only":
                    d[name].append(("On Demand Only", m.group(1)))
                if line[:13] == "Max MPX/drive":
                    d[name].append(("Max MPX/drive", m.group(1)))
                if line[:7] == "Density":
                    d[name].append(("Density", m.group(1)))
                if line[:17] == "Robot Type/Number":
                    d[name].append(("Robot Type/Number", m.group(1)))
                if line[:17] == "Max Fragment Size":
                    d[name].append(("Max Fragment Size", m.group(1)))
            elif t == "Disk":
                if line[:20] == "Storage Unit Subtype":
                    d[name].append(("Storage Unit Subtype", m.group(1)))
                if line[:15] == "Host Connection":
                    d[name].append(("Host Connection", m.group(1)))
                if line[:15] == "Concurrent Jobs":
                    d[name].append(("Concurrent Jobs", m.group(1)))
                if line[:14] == "On Demand Only":
                    d[name].append(("On Demand Only", m.group(1)))
                if line[:7] == "Max MPX":
                    d[name].append(("Max MPX", m.group(1)))
                if line[:17] == "Max Fragment Size":
                    d[name].append(("Max Fragment Size", m.group(1)))
                if line[:13] == "Block Sharing":
                    d[name].append(("Block Sharing", m.group(1)))
                if line[:10] == "Ok On Root":
                    d[name].append(("Ok On Root", m.group(1)))
            if line[:14] == "Disk Pool Name":
                poolname = m.group(1)
                self.pools[poolname] = list()
                self.pools[poolname].append(("Disk Pool Name", m.group(1)))
            if line[:14] == "Disk Pool Id":
                self.pools[poolname].append(("Disk Pool Id", m.group(1)))
            if line[:10] == "Disk Type ":
                self.pools[poolname].append(("Disk Type", m.group(1)))
            if line[:8] == "Status  ":
                self.pools[poolname].append(("Status", m.group(1)))
            if line[:11] == "Num Volumes":
                self.pools[poolname].append(("Num Volumes", m.group(1)))
            if line[:14] == "High Watermark":
                self.pools[poolname].append(("High Watermark", m.group(1)))
            if line[:13] == "Low Watermark":
                self.pools[poolname].append(("Low Watermark", m.group(1)))
            if line[:14] == "Max IO Streams":
                self.pools[poolname].append(("Max IO Streams", m.group(1)))
            if line[:8] == "Raw Size":
                self.pools[poolname].append(("Raw Size", m.group(1)))

        for stu in d:
            if d[stu][1][0] == "Storage Unit Type" and d[stu][1][1] == "Media Manager":
                self.stuMM[stu] = d[stu]
            else:
                self.stuDisk[stu] = d[stu]
        if "MM_vmpool.txt" not in self.cont:
            self.cont["MM_vmpool.txt"] = "empty"
        for line in self.cont["MM_vmpool.txt"]:
            if line[:9] == "pool name":
                name = match(".*: +(.*)", line).group(1)
            if line[:11] == "description":
                desc = match(".*: +(.*)", line).group(1)
                self.vpools.append((name, desc))
        if "NBU_bppllist.txt" not in self.cont:
            self.cont["NBU_bppllist.txt"] = "empty"
        self.policies = Policies(self.cont["NBU_bppllist.txt"])
        self.slps = SLPs(self.cont["NBU_nbstl.txt"])
        self.diskpools = DiskPools(self.cont["NBU_adv_disk.txt"])


class customer_info:
    def __init__(self):
        self.CustomerShortName = str
        self.CustomerFullName = str
        self.Number = str
        self.SID = str
        self.SAN = str
        self.contacts = list()


def build_document(nb, cinfo, descr):
    env = Environment(loader=FileSystemLoader("res"))
    template = env.get_template('cam_tmpl.html')
    f = open(cinfo.CustomerShortName + ".html", "w")
    f.write(str(template.render(data=nb, customer=cinfo, desc=descr)).encode('utf-8'))
    f.close()
    print "Content-Type: text/html; charset=utf-8;"
    print "Location: " + cinfo.CustomerShortName + ".html"
    print

try:
    msvcrt.setmode(0, os.O_BINARY)
    msvcrt.setmode(1, os.O_BINARY)
    cinfo = customer_info
    form = cgi.FieldStorage()
    upload = form["nbsu"]
    diagram = form["diagram"]
    cinfo.CustomerShortName = str(form["CustomerShortName"].value)
    cinfo.CustomerFullName = str(form["CustomerFullName"].value)
    cinfo.Number = str(form["Number"].value)
    cinfo.SID = str(form["SID"].value)
    cinfo.SAN = str(form["SAN"].value)
    cinfo.contacts = list()
    cinfo.contacts.append((form["CName1"].value, form["CMob1"].value, form["CLan1"].value, form["CEma1"].value))
    cinfo.contacts.append((form["CName2"].value, form["CMob2"].value, form["CLan2"].value, form["CEma2"].value))
    cinfo.contacts.append((form["CName3"].value, form["CMob3"].value, form["CLan3"].value, form["CEma3"].value))
    cinfo.contacts.append((form["CName4"].value, form["CMob4"].value, form["CLan4"].value, form["CEma4"].value))
    cinfo.contacts.append((form["CName5"].value, form["CMob5"].value, form["CLan5"].value, form["CEma5"].value))
    if not os.path.exists(cinfo.CustomerShortName):
        os.makedirs(cinfo.CustomerShortName)
    if upload.filename is not None:
        name = cinfo.CustomerShortName + "/" + os.path.basename(upload.filename)
        out = open(name, 'wb', 1000)
        while True:
            packet = upload.file.read(1000)
            if not packet:
                break
            out.write(packet)
        out.close()
        zfile = zipfile.ZipFile(name)
        for name in zfile.namelist():
            (dirname, filename) = os.path.split(name)
            zfile.extract(name, cinfo.CustomerShortName)
            if filename == "nbsu_info.txt":
                root = cinfo.CustomerShortName + "/" + dirname
        if diagram.filename is not None:
            out = open(cinfo.CustomerShortName + "/diagram.jpg", 'wb', 1000)
            while True:
                packet = diagram.file.read(1000)
                if not packet:
                    break
                out.write(packet)
            out.close()
    nb = NBSU(root)
    build_document(nb, cinfo, str(form["desc"].value)[1:].encode('utf-8'))

except:
    f = open(cinfo.CustomerShortName + ".html", 'r')
    traceback.print_exc(file=f)

# nb = NBSU(r"C:\Users\vorop_000\Documents\nbumaster")
# c = customer_info
# c.CustomerShortName = "test"
# c.CustomerFullName = "test"
# c.Number = "test"
# c.SID = "test"
# c.SAN = "test"
# c.contacts = list()
# build_document(nb, c, "sd")
#
#



