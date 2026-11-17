#!/usr/bin/python
# #############################################################################
# #############################################################################
# MLB Python Program Management (PyProgMan) Module Script
# #############################################################################
#
#   File Name       :   ProcCtl.py
#
#   File Description:   Test file for the MLB::Utility Python interface.
#
#   Revision History:   2009-02-19 --- Creation in a Perl script suite.
#                               Michael L. Brock
#                       2025-09-22 --- Logic migrated to Python.
#
#       Copyright Michael L. Brock 2007 - 2026.
#       Distributed under the Boost Software License, Version 1.0.
#       (See accompanying file LICENSE_1_0.txt or copy at
#       http://www.boost.org/LICENSE_1_0.txt)
#
# #############################################################################

# #############################################################################
import psutil
import re

from typing import Any
# #############################################################################

# #############################################################################
def FixUpVoE(value: int) -> str:
    if (value == 1):
        return("is")

    return("are")
# #############################################################################

# #############################################################################
def FixUpVoEPlus(value: int) -> str:
    return(FixUpVoE(value) + " " + str(value))
# #############################################################################

# #############################################################################
def FixUpPlural(value: int) -> str:
    if (value == 1):
        return("")

    return("s")
# #############################################################################

# #############################################################################
def GetSep(sep_char: str = "", width: int = 79) -> str:
    result: str = ""

    if (width > 0):
        if (len(sep_char) > 0):
            tmp_char: str = sep_char[0]
        else:
            tmp_char: str = "="

        result = tmp_char * width

    return(result)
# #############################################################################

# #############################################################################
def EmitSep(sep_char: str = "", width: int = 79):
    print(GetSep(sep_char, width))
# #############################################################################

# #############################################################################
def UnderlineString(src: str) -> str:
    str_len: int = len(src)
    underline: str = "-" * (str_len + 1)
    return(src + ":\n" + underline)
# #############################################################################

# #############################################################################
def ThrowTypeNotInDomain(func_name: str, param_name: str,
                         param_type: str) -> None:
    raise TypeError("Invocation of function '" + func_name + "()' "
                     "with a '" + param_name + "' parameter of an "
                     "unsupported type (" + param_type + ").")
# #############################################################################

# #############################################################################
# *****************************************************************************
# *****************************************************************************
# *****************************************************************************
# #############################################################################

# #############################################################################
def GetProcsBasic(all_procs: bool = True,
                  src_attrs: list[str] = []) -> dict[int, dict]:
    results  : dict[int, dict] = {}
    tmp_attrs: list[str]       = src_attrs
    mod_attrs: bool            = False
    if ((all_procs == False) and
        (len(tmp_attrs) > 0) and ("cwd" not in tmp_attrs)):
        mod_attrs = True
        tmp_attrs.append("cwd")
    for this_proc in psutil.process_iter():
        this_data: dict = this_proc.as_dict(tmp_attrs, None)
        this_pid:  int  = this_data["pid"]
        if ((this_pid != None) and
            (all_procs or (this_data["cwd"] is not None))):
            results[this_pid] = this_data;
            if (mod_attrs):
                del results[this_pid]["cwd"]

    return results
# #############################################################################

# #############################################################################
def GetProcs(all_procs: bool = False) -> dict[int, dict]:
    return(GetProcsBasic(all_procs, ["pid", "exe"]))
# #############################################################################

# #############################################################################
def GetProcsInterpreter(all_procs: bool = False) -> dict[int, dict]:
    return(GetProcsBasic(all_procs, ["pid", "exe", "cmdline"]))
# #############################################################################

# #############################################################################
def FilterProcsByPID(src_pid_spec: int | list[int] | set[int],
                     src_proc_list: dict[int, dict] =
                     GetProcs()) -> dict[int, dict]:
    tmp_pid_spec: set[int] = set()

    if (type(src_pid_spec) is int):
        tmp_pid_spec = {src_pid_spec}
    elif (type(src_pid_spec) is list):
        tmp_pid_spec = set(src_pid_spec)
    elif (type(src_pid_spec) is set):
        tmp_pid_spec = src_pid_spec
    else:
        ThrowTypeNotInDomain("FilterProcsByPID", "src_pid_spec",
                             str(type(src_pid_spec)))

    dst_proc_list: dict[int, dict] = {}

    for this_key in src_proc_list:
        if (this_key in tmp_pid_spec):
            dst_proc_list[this_key] = src_proc_list[this_key]

    return(dst_proc_list)
# #############################################################################

# #############################################################################
def GetProcsByPID(src_pid_spec: int | list[int] | set[int]) -> dict[int, dict]:
    return(FilterProcsByPID(src_pid_spec, GetProcs()))
# #############################################################################

# #############################################################################
def GetProcsInterpreterByPID(src_pid_spec: int | list[int] |
                             set[int]) -> dict[int, dict]:
    return(FilterProcsByPID(src_pid_spec, GetProcsInterpreter()))
# #############################################################################

# #############################################################################
def FilterProcsByPattern(src_pattern_spec: str | re.Pattern,
                         src_proc_list: dict[int, dict] =
                         GetProcs()) -> dict[int, dict]:
    if (type(src_pattern_spec) is str):
        tmp_pattern_spec: re.Pattern = re.compile(re.escape(src_pattern_spec))
    elif (type(src_pattern_spec) is re.Pattern):
        tmp_pattern_spec = src_pattern_spec
    else:
        ThrowTypeNotInDomain("FilterProcsByPattern", "src_pattern_spec",
                             str(type(src_pattern_spec)))

    dst_proc_list: dict[int, dict] = {}
    for this_key in src_proc_list:
        pattern_match = tmp_pattern_spec.search(str(src_proc_list[this_key]))
        if (type(pattern_match) is re.Match):
            dst_proc_list[this_key] = src_proc_list[this_key]

    return(dst_proc_list)
# #############################################################################

# #############################################################################
def GetProcsByBaseName(base_name: str,
                       proc_list: dict[int, dict] =
                       GetProcs()) -> dict[int, dict]:
    if (not base_name):
        raise ValueError("Invocation with an empty process base name.")

    return(FilterProcsByPattern(
        re.compile("'exe': '.*\\/" + re.escape(base_name) + ".*'"), proc_list))
# #############################################################################

# #############################################################################
def RequireProcsByBaseName(base_name: str, min_count: int = 0,
                           max_count: int | None = None,
                           proc_list: dict[int, dict] =
                           GetProcs()) -> dict[int, dict]:
    max_count = max_count if max_count else min_count
    if (min_count > max_count):
        raise ValueError("The minimum count (" + str(min_count) + ") is " +
                         "greater than the maximum count (" +
                         str(max_count) + ").")

    result_procs: dict[int, dict] = GetProcsByBaseName(base_name, proc_list)
    result_count: int             = len(result_procs)

    if ((result_count < min_count) or (result_count > max_count)):
        raise ValueError("There " + FixUpVoEPlus(result_count) + " instance" +
                         FixUpPlural(result_count) + " of base name " +
                         "program '" + base_name + "' running, which is "
                         "outside the expected range of " + str(min_count) +
                         " to " + str(max_count) + " instance" +
                         FixUpPlural(max_count) + ", inclusive.")

    return(result_procs)
# #############################################################################

# #############################################################################
def RequireProcsByBaseNameNone(base_name: str,
                               proc_list: dict[int, dict] =
                               GetProcs()) -> dict[int, dict]:

    return(RequireProcsByBaseName(base_name, 0, 0, proc_list))
# #############################################################################

# #############################################################################
def RequireProcsByBaseNameSingle(base_name: str,
                               proc_list: dict[int, dict] =
                               GetProcs()) -> dict[int, dict]:

    return(RequireProcsByBaseName(base_name, 1, 1, proc_list))
# #############################################################################

# #############################################################################
def EmitProcsDict(proc_dict: dict[int, dict],
                  keys_spec: str | dict[str, Any] | list[str] | set[str] |
                  None = None) -> None:
    if (not proc_dict):
        return

    tmp_keys_spec: set[str] = set()
    keys_for_proc: set[str] = set(proc_dict[next(iter(proc_dict))].keys())
    if ((keys_spec is not None) and (len(keys_spec) > 0) and
        (len(proc_dict) > 0)):
        if (type(keys_spec) is str):
            tmp_keys_spec = {keys_spec} & keys_for_proc
        elif (type(keys_spec) is dict):
            tmp_keys_spec = set(keys_spec.keys()) & keys_for_proc
        elif (type(keys_spec) is list):
            tmp_keys_spec = set(keys_spec) & keys_for_proc
        elif (type(keys_spec) is set):
            tmp_keys_spec = keys_spec & keys_for_proc

    tmp_keys_list: list[str] = []
    if (not tmp_keys_spec):
        tmp_keys_list = sorted(keys_for_proc)
    else:
        tmp_keys_list = sorted(tmp_keys_spec)

    for this_key in sorted(proc_dict.keys()):
        proc_datum: dict[str, Any] = {}
        for datum_key in tmp_keys_list:
            proc_datum[datum_key] = proc_dict[this_key][datum_key]
        print(f"{this_key:>7}:", proc_datum)
# #############################################################################

# #############################################################################
# *****************************************************************************
# *****************************************************************************
# *****************************************************************************
# #############################################################################

# #############################################################################
import random
import sys
import traceback
# #############################################################################

# #############################################################################
def _TEST_ProcDictTypes(proc_list: dict[int, dict]) -> None:
    print("==================================================================")
    print(UnderlineString("_TEST_ProcDictTypes(): " +
                          str(len(proc_list)) + " processes"))
    print("type of proc_list            :", type(proc_list))
    print("type of proc_list.keys()     :", type(proc_list.keys()))
    print("type of set(proc_list.keys()):", type(set(proc_list.keys())))
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_DumpAllProcs(proc_list: dict[int, dict]) -> None:
    print("==================================================================")
    print(UnderlineString("_TEST_DumpAllProcs(): " +
                          str(len(proc_list)) + " processes"))
    EmitProcsDict(proc_list)
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_RegexPatternTypes() -> None:
    print("==================================================================")
    print(UnderlineString("_TEST_RegexPatternTypes()"))
    X_pattern_spec: re.Pattern = re.compile("python")
    X_pattern_match = re.search(X_pattern_spec, "XXX-python-YYY")
    X_pattern_match = re.search(X_pattern_spec, "/usr/bin/python3.14")
    print(">>> Type of pattern_spec    : ", type(X_pattern_spec))
    print(">>> Value of pattern_spec   : ", X_pattern_spec)
    print(">>> Type of pattern_match   : ", type(X_pattern_match))
    print(">>> Value of pattern_match  : ", X_pattern_match)
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_FilterProcsByPattern() -> None:
    print("==================================================================")
    print(UnderlineString("FilterProcsByPattern(): 'python'"))
    EmitProcsDict(
        FilterProcsByPattern("python"))
    print("------------------------------------------------------------------")
    print(UnderlineString(
        "FilterProcsByPattern(): 'exe': '.*\\/python(\\d+\\.\\d+)?.*'"))
    EmitProcsDict(
        FilterProcsByPattern(
            re.compile("'exe': '.*\\/python(\\d+\\.\\d+)?.*'")))
    print("------------------------------------------------------------------")
    try:
        EmitProcsDict(FilterProcsByPattern(1.23))
    except Exception as this_except:
        print("ANTICIPATED ERROR: Error in '_TEST_FilterProcsByPattern()' "
              "internal test: ", this_except)
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_FilterProcsByPID() -> None:
    my_proc = psutil.Process()
    my_pid  = my_proc.pid
    print("==================================================================")
    print(UnderlineString("FilterProcsByPID(): " + str(my_pid)))
    EmitProcsDict(
        FilterProcsByPID(my_pid))
    print("------------------------------------------------------------------")
    print(UnderlineString("FilterProcsByPID(): [" + str(my_pid) + "]"))
    EmitProcsDict(
        FilterProcsByPID([my_pid]))
    print("------------------------------------------------------------------")
    print(UnderlineString("FilterProcsByPID(): [" + str(my_pid) + ", " +
                          str(my_pid) + ", " + str(my_pid) + "]"))
    EmitProcsDict(
        FilterProcsByPID([my_pid, my_pid, my_pid]))
    print("------------------------------------------------------------------")
    print(UnderlineString("FilterProcsByPID(): {" + str(my_pid) + ", " +
                          str(my_pid) + ", " + str(my_pid) + "}"))
    EmitProcsDict(
        FilterProcsByPID({my_pid, my_pid, my_pid}))
    print("------------------------------------------------------------------")
    all_pid_dict : dict[int, dict] = GetProcs(False)
    all_pid_list : list[int]       = list(all_pid_dict.keys())
    test_pid_set : set[int]        = {my_pid}
    first_bad_pid: int             = max(all_pid_dict) + 1
    if (first_bad_pid <= 100000):
        first_bad_pid = 100000
    elif (first_bad_pid <= 1000000):
        first_bad_pid =    1000000
    elif (first_bad_pid <= 1000000):
        first_bad_pid =   10000000
    elif (first_bad_pid <= 1000000):
        first_bad_pid =  100000000
    elif (first_bad_pid <= 1000000):
        first_bad_pid = 1000000000
    # ----- Must have at least four valid PIDs:
    all_pid_count: int = len(all_pid_dict)
    if (all_pid_count < 4):
        raise ValueError("There are two few matching processes running (" +
                         str(all_pid_count) + ") --- a minimum of four " +
                         "active processes are required for this test.")
    # ----- Add three additional valid PIDs:
    while len(test_pid_set) < 4:
        try_pid_index: int = random.randint(0, all_pid_count - 1)
        test_pid_set.add(all_pid_list[try_pid_index])
    # ----- Add three additional invalid PIDs:
    while len(test_pid_set) < 7:
        test_pid_set.add(random.randint(first_bad_pid, first_bad_pid + 100))
    print(UnderlineString("FilterProcsByPID(): " + str(test_pid_set)))
    EmitProcsDict(
        FilterProcsByPID(test_pid_set, all_pid_dict))
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_GetProcsByBaseName() -> None:
    print("==================================================================")
    print(UnderlineString("GetProcsByBaseName(): python"))
    EmitProcsDict(
        GetProcsByBaseName("python"))
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_EmitProcsDict() -> None:
    print("==================================================================")
    attrs: list[str] = ["pid", "exe", "cmdline", "cwd", "username", "ppid"]
    test_proc_list = GetProcsByBaseName("python", GetProcsBasic(True, attrs))
    print("TEST USING GetProcsByBaseName('python',\n" +
          "    GetProcsBasic(True,\n" +
          "        " + str(attrs) + ")) =\n" +
          "        " + str(len(test_proc_list)) + " processes")
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Default keys (all keys)"))
    EmitProcsDict(test_proc_list)
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key 'cwd'"))
    EmitProcsDict(test_proc_list, "cwd")
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key 'username'"))
    EmitProcsDict(test_proc_list, "username")
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key ['cwd', 'username']"))
    EmitProcsDict(test_proc_list, ['cwd', 'username'])
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key {'cwd', 'username'}"))
    EmitProcsDict(test_proc_list, {'cwd', 'username'})
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key ['cwd', 'bad', 'worse', 'username']"))
    EmitProcsDict(test_proc_list, ['cwd', 'bad', 'worse', 'username'])
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key ['cwd', 'bad', 'worse', 'username', 'status']"))
    EmitProcsDict(test_proc_list, ['cwd', 'bad', 'worse', 'username', 'status'])
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key ['pid', 'exe', 'cmdline', 'cwd', 'username', 'ppid']"))
    EmitProcsDict(test_proc_list, ["pid", "exe", "cmdline", "cwd", "username", "ppid"])
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key None"))
    EmitProcsDict(test_proc_list, None)
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key ''"))
    EmitProcsDict(test_proc_list, '')
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key []"))
    EmitProcsDict(test_proc_list, [])
    print("------------------------------------------------------------------")
    print(UnderlineString("EmitProcsDict(): Key {}"))
    EmitProcsDict(test_proc_list, {})
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
def _TEST_RequireProcsByBaseName() -> None:
    print("==================================================================")
    print(UnderlineString("RequireProcsByBaseName(): 'python', 1, 2"))
    EmitProcsDict(RequireProcsByBaseName("python", 1, 2))
    print("==================================================================")
    print("")
# #############################################################################

# #############################################################################
if __name__ == "__main__":
    try:
        proc_list: dict[int, dict] = GetProcs()
        _TEST_ProcDictTypes(proc_list)
        _TEST_DumpAllProcs(proc_list)
        _TEST_RegexPatternTypes()
        _TEST_FilterProcsByPattern()
        _TEST_FilterProcsByPID()
        _TEST_GetProcsByBaseName()
        _TEST_EmitProcsDict()
        _TEST_RequireProcsByBaseName()
    except Exception as this_except:
        print("ERROR: Error in 'ProcCtl.py' internal test: ", this_except,
              file=sys.stderr)
        print(traceback.format_exc())
# #############################################################################

