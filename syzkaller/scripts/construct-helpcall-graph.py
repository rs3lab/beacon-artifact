import re, sys, os
import json

# Sorry for spaghetti code
# Contact Pragyansh (GitHub: r41k0u) for any changes


def extractP2G(linux_src):
    ptype2GFPsuffix = dict()

    with open("{}/include/linux/bpf_types.h".format(linux_src), "r") as f:
        lines = f.read().split("\n")
        for line in lines:
            if "BPF_PROG_TYPE" in line:
                tmp = line.split("(")[1].split(",")
                progtype = tmp[0]
                get_func_proto_suffix = tmp[1]
                ptype2GFPsuffix[progtype] = get_func_proto_suffix.replace(" ", "")

    return ptype2GFPsuffix


def ptype2get_func_proto(get_func_proto_suffix, linux_src):
    cmd = 'grep --include=*.c -rn "bpf_verifier_ops {}" {}'.format(
        get_func_proto_suffix, linux_src
    )
    loc = os.popen(cmd).read()
    if loc == "":
        return ""  # "can't find {} through grep".format(get_func_proto_suffix)
    else:
        fn = loc.split(":")[0]
        lno = int(loc.split(":")[1])
        with open(fn, "r") as f:
            lines = f.read().split("\n")
            i = lno
            while True:
                if lines[i] == "};":
                    return ""  # "{} doesn't have .get_func_proto".format(get_func_proto_suffix)
                elif ".get_func_proto" in lines[i]:
                    return lines[i].split("=")[1].split(",")[0]
                i += 1


def extract_related_helpers(linux_src, get_func_proto):
    cmd = "bash {}/list_helpers_of_one_progtype.sh {} {}".format(
        os.path.dirname(os.path.abspath(__file__)), linux_src, get_func_proto
    )
    helpers = os.popen(cmd).read().split("\n")
    if len(helpers) != 0:
        return helpers[:-1]
    else:
        return list()


def extract_helper_info(linux_src):
    helpers_info = dict()
    indep_args = [
        "SCALAR_VALUE",
        "PTR_TO_STACK",
        "PTR_TO_CTX",
        "ARG_ANYTHING",
        "CONST_PTR_TO_MAP",
        "ARG_PTR_TO_STACK_OR_NULL"
    ]
    dep_args = [
        "PTR_TO_MEM",
        "PTR_TO_SOCKET",
        "PTR_TO_SOCK_COMMON",
        "PTR_TO_TCP_SOCK",
        #"PTR_TO_BTF_ID",
        "PTR_TO_MAP_VALUE",
        #"ARG_PTR_TO_BTF_ID_OR_NULL",
        "ARG_PTR_TO_MEM_OR_NULL",
        "ARG_PTR_TO_MAP_VALUE_OR_NULL"
    ]
    ret2basetype = {
        "RET_PTR_TO_BTF_ID": ["PTR_TO_BTF_ID"],
        "RET_PTR_TO_BTF_ID_OR_NULL": ["PTR_TO_BTF_ID"],
        "RET_PTR_TO_BTF_ID_TRUSTED": ["PTR_TO_BTF_ID"],
        "RET_PTR_TO_DYNPTR_MEM_OR_NULL": ["PTR_TO_MEM"],
        "RET_PTR_TO_MAP_VALUE": ["PTR_TO_MAP_VALUE"],
        "RET_PTR_TO_MAP_VALUE_OR_NULL": ["PTR_TO_MAP_VALUE"],
        "RET_PTR_TO_MEM_OR_BTF_ID": ["PTR_TO_MEM", "PTR_TO_BTF_ID"],
        "RET_PTR_TO_RINGBUF_MEM_OR_NULL": ["PTR_TO_MEM", "MEM_RINGBUF"],
        "RET_PTR_TO_SOCK_COMMON_OR_NULL": ["PTR_TO_SOCK_COMMON"],
        "RET_PTR_TO_SOCKET_OR_NULL": ["PTR_TO_SOCKET"],
        "RET_PTR_TO_TCP_SOCK_OR_NULL": ["PTR_TO_TCP_SOCK"],
        "RET_INTEGER": ["INTEGER"],
        "RET_VOID": ["VOID"],
    }

    mem_types = (
        [
            "PTR_TO_STACK",
            "PTR_TO_PACKET",
            "PTR_TO_PACKET_META",
            "PTR_TO_MAP_KEY",
            "PTR_TO_MAP_VALUE",
            "PTR_TO_MEM",
            ["PTR_TO_MEM", "MEM_RINGBUF"],
            "PTR_TO_BUF",
            ["PTR_TO_BTF_ID", "PTR_TRUSTED"],
        ],
    )

    sock_types = [
        "PTR_TO_SOCK_COMMON",
        "PTR_TO_SOCKET",
        "PTR_TO_TCP_SOCK",
        "PTR_TO_XDP_SOCK",
    ]

    btf_id_sock_common_types = [
        "PTR_TO_SOCK_COMMON",
        "PTR_TO_SOCKET",
        "PTR_TO_TCP_SOCK",
        "PTR_TO_XDP_SOCK",
        "PTR_TO_BTF_ID",
        ["PTR_TO_BTF_ID", "PTR_TRUSTED"],
    ]

    int_ptr_types = [
        "PTR_TO_STACK",
        "PTR_TO_PACKET",
        "PTR_TO_PACKET_META",
        "PTR_TO_MAP_KEY",
        "PTR_TO_MAP_VALUE",
    ]

    spin_lock_types = ["PTR_TO_MAP_VALUE", ["PTR_TO_BTF_ID", "MEM_ALLOC"]]

    fullsock_types = ["PTR_TO_SOCKET"]
    scalar_types = ["SCALAR_VALUE"]
    context_types = ["PTR_TO_CTX"]
    ringbuf_mem_types = ["PTR_TO_MEM", "MEM_RINGBUF"]
    const_map_ptr_types = ["CONST_PTR_TO_MAP"]

    btf_ptr_types = [
        "PTR_TO_BTF_ID",
        ["PTR_TO_BTF_ID", "PTR_TRUSTED"],
        ["PTR_TO_BTF_ID", "MEM_RCU"],
    ]

    percpu_btf_ptr_types = [
        ["PTR_TO_BTF_ID", "MEM_PERCPU"],
        ["PTR_TO_BTF_ID", "MEM_PERCPU", "PTR_TRUSTED"],
    ]

    func_ptr_types = ["PTR_TO_FUNC"]
    stack_ptr_types = ["PTR_TO_STACK"]
    const_str_ptr_types = ["PTR_TO_MAP_VALUE"]
    timer_types = ["PTR_TO_MAP_VALUE"]
    kptr_types = ["PTR_TO_MAP_VALUE"]
    dynptr_types = [
        "PTR_TO_STACK",
        "CONST_PTR_TO_DYNPTR",
    ]

    arg2basetype = {
        "ARG_PTR_TO_MAP_KEY": mem_types,
        "ARG_PTR_TO_MAP_VALUE": mem_types,
        "ARG_CONST_SIZE": scalar_types,
        "ARG_CONST_SIZE_OR_ZERO": scalar_types,
        "ARG_CONST_ALLOC_SIZE_OR_ZERO": scalar_types,
        "ARG_CONST_MAP_PTR": const_map_ptr_types,
        "ARG_PTR_TO_CTX": context_types,
        "ARG_PTR_TO_SOCK_COMMON": sock_types,
        "ARG_PTR_TO_BTF_ID_SOCK_COMMON": btf_id_sock_common_types,
        "ARG_PTR_TO_SOCKET": fullsock_types,
        "ARG_PTR_TO_BTF_ID": btf_ptr_types,
        "ARG_PTR_TO_SPIN_LOCK": spin_lock_types,
        "ARG_PTR_TO_MEM": mem_types,
        "ARG_PTR_TO_RINGBUF_MEM": ringbuf_mem_types,
        "ARG_PTR_TO_INT": int_ptr_types,
        "ARG_PTR_TO_LONG": int_ptr_types,
        "ARG_PTR_TO_PERCPU_BTF_ID": percpu_btf_ptr_types,
        "ARG_PTR_TO_FUNC": func_ptr_types,
        "ARG_PTR_TO_STACK": stack_ptr_types,
        "ARG_PTR_TO_CONST_STR": const_str_ptr_types,
        "ARG_PTR_TO_TIMER": timer_types,
        "ARG_PTR_TO_KPTR": kptr_types,
        "ARG_PTR_TO_DYNPTR": dynptr_types,
    }

    cmd = 'grep -rn  "struct bpf_func_proto .* = {{" {}'.format(linux_src)

    locs = os.popen(cmd).read().split("\n")
    for loc in locs:
        if loc == "":
            continue
        # if "bpf_ringbuf_reserve_dynptr" in loc:
        # 	pdb.set_trace()
        fn = loc.split(":")[0]
        lno = int(loc.split(":")[1])

        func_info = dict()
        with open(fn, "r") as f:
            lines = f.read().split("\n")
            # print(lines[lno-1])
            proto_name = lines[lno - 1].split(" ")[
                -3
            ]  # lines[lno-1].split("=")[1][1:-1]
            i = lno
            while True:
                lines[i] = lines[i].replace("\t", " ")
                if lines[i] == "};":
                    break
                elif re.search("\..*= ", lines[i]):
                    tmp = re.findall(".*\.(.*?) *= (\S+)( |$)", lines[i])[0]
                    item = tmp[0]
                    value = tmp[1].replace(",", "")
                    # 'ret_type': 'RET_INTEGER'
                    if item == "ret_type":
                        value = ret2basetype[value]
                    if re.search("arg[1-9]_type", item) and value in arg2basetype:
                        value = arg2basetype[value]
                    func_info[item] = value
                    # print(proto_name, value)
                i += 1
            helpers_info[proto_name] = func_info
            # print(proto_name, func_info)
    topop = []
    for ke, i in helpers_info.items():
        if "ret_type" not in i.keys():
            continue
        if i["ret_type"][0] == "PTR_TO_BTF_ID":
            topop.append(ke)
    for i in topop:
        helpers_info.pop(i)
    # Making the independent array AND DEPENDENT ARRAY
    tot_args = indep_args + dep_args
    indep_arr = {}
    dep_arr_temp = {}
    for ke, i in helpers_info.items():
        args = [0] * 5
        if "arg5_type" in i.keys():
            if (type(i["arg5_type"]) == str):
                if (i["arg5_type"] in indep_args):
                    args[-1] = 1
            elif (type(i["arg5_type"][0]) == list) and len(i["arg5_type"][0]) > 2:
                for j in i["arg5_type"][0]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-1] = 1
                    else:
                        if j[0] in indep_args:
                            args[-1] = 1
            else:
                for j in i["arg5_type"]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-1] = 1
                    else:
                        if j[0] in indep_args:
                            args[-1] = 1
        else:
            args[-1] = 1
        if "arg4_type" in i.keys():
            if (type(i["arg4_type"]) == str):
                if (i["arg4_type"] in indep_args):
                    args[-2] = 1
            elif (type(i["arg4_type"][0]) == list) and len(i["arg4_type"][0]) > 2:
                for j in i["arg4_type"][0]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-2] = 1
                    else:
                        if j[0] in indep_args:
                            args[-2] = 1
            else:
                for j in i["arg4_type"]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-2] = 1
                    else:
                        if j[0] in indep_args:
                            args[-2] = 1
        else:
            args[-2] = 1
        if "arg3_type" in i.keys():
            if (type(i["arg3_type"]) == str):
                if (i["arg3_type"] in indep_args):
                    args[-3] = 1
            elif (type(i["arg3_type"][0]) == list) and len(i["arg3_type"][0]) > 2:
                for j in i["arg3_type"][0]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-3] = 1
                    else:
                        if j[0] in indep_args:
                            args[-3] = 1
            else:
                for j in i["arg3_type"]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-3] = 1
                    else:
                        if j[0] in indep_args:
                            args[-3] = 1
        else:
            args[-3] = 1
        if "arg2_type" in i.keys():
            if (type(i["arg2_type"]) == str):
                if (i["arg2_type"] in indep_args):
                    args[-4] = 1
            elif (type(i["arg2_type"][0]) == list) and len(i["arg2_type"][0]) > 2:
                for j in i["arg2_type"][0]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-4] = 1
                    else:
                        if j[0] in indep_args:
                            args[-4] = 1
            else:
                for j in i["arg2_type"]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-4] = 1
                    else:
                        if j[0] in indep_args:
                            args[-4] = 1
        else:
            args[-4] = 1
        if "arg1_type" in i.keys():
            if (type(i["arg1_type"]) == str):
                if (i["arg1_type"] in indep_args):
                    args[-5] = 1
            elif (type(i["arg1_type"][0]) == list) and len(i["arg1_type"][0]) > 2:
                for j in i["arg1_type"][0]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-5] = 1
                    else:
                        if j[0] in indep_args:
                            args[-5] = 1
            else:
                for j in i["arg1_type"]:
                    if type(j) == str:
                        if j in indep_args:
                            args[-5] = 1
                    else:
                        if j[0] in indep_args:
                            args[-5] = 1
        else:
            args[-5] = 1
        if sum(args) == 5:
            indep_arr[ke] = i
    
    for ke, i in helpers_info.items():
        args = [0] * 5
        if "arg5_type" in i.keys():
            if (type(i["arg5_type"]) == str):
                if (i["arg5_type"] in tot_args):
                    args[-1] = 1
            elif (type(i["arg5_type"][0]) == list) and len(i["arg5_type"][0]) > 2:
                for j in i["arg5_type"][0]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-1] = 1
                    else:
                        if j[0] in tot_args:
                            args[-1] = 1
            else:
                for j in i["arg5_type"]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-1] = 1
                    else:
                        if j[0] in tot_args:
                            args[-1] = 1
        else:
            args[-1] = 1
        if "arg4_type" in i.keys():
            if (type(i["arg4_type"]) == str):
                if (i["arg4_type"] in tot_args):
                    args[-2] = 1
            elif (type(i["arg4_type"][0]) == list) and len(i["arg4_type"][0]) > 2:
                for j in i["arg4_type"][0]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-2] = 1
                    else:
                        if j[0] in tot_args:
                            args[-2] = 1
            else:
                for j in i["arg4_type"]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-2] = 1
                    else:
                        if j[0] in tot_args:
                            args[-2] = 1
        else:
            args[-2] = 1
        if "arg3_type" in i.keys():
            if (type(i["arg3_type"]) == str):
                if (i["arg3_type"] in tot_args):
                    args[-3] = 1
            elif (type(i["arg3_type"][0]) == list) and len(i["arg3_type"][0]) > 2:
                for j in i["arg3_type"][0]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-3] = 1
                    else:
                        if j[0] in tot_args:
                            args[-3] = 1
            else:
                for j in i["arg3_type"]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-3] = 1
                    else:
                        if j[0] in tot_args:
                            args[-3] = 1
        else:
            args[-3] = 1
        if "arg2_type" in i.keys():
            if (type(i["arg2_type"]) == str):
                if (i["arg2_type"] in tot_args):
                    args[-4] = 1
            elif (type(i["arg2_type"][0]) == list) and len(i["arg2_type"][0]) > 2:
                for j in i["arg2_type"][0]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-4] = 1
                    else:
                        if j[0] in tot_args:
                            args[-4] = 1
            else:
                for j in i["arg2_type"]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-4] = 1
                    else:
                        if j[0] in tot_args:
                            args[-4] = 1
        else:
            args[-4] = 1
        if "arg1_type" in i.keys():
            if (type(i["arg1_type"]) == str):
                if (i["arg1_type"] in tot_args):
                    args[-5] = 1
            elif (type(i["arg1_type"][0]) == list) and len(i["arg1_type"][0]) > 2:
                for j in i["arg1_type"][0]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-5] = 1
                    else:
                        if j[0] in tot_args:
                            args[-5] = 1
            else:
                for j in i["arg1_type"]:
                    if type(j) == str:
                        if j in tot_args:
                            args[-5] = 1
                    else:
                        if j[0] in tot_args:
                            args[-5] = 1
        else:
            args[-5] = 1
        if sum(args) == 5:
            dep_arr_temp[ke] = i

    dep_arr = {keyt: valt for keyt, valt in dep_arr_temp.items() if keyt not in indep_arr.keys()}
    sorted_by_ret = {}
    for _, itet in indep_arr.items():
        if "ret_type" in itet.keys():
            for i in itet["ret_type"]:
                if i in dep_args:
                    if i not in sorted_by_ret.keys():
                        sorted_by_ret[i] = []
                    sorted_by_ret[i].append(itet)
                    break
    return helpers_info, indep_arr, dep_arr, sorted_by_ret


def build_graph(helper_info):
    graph = dict()

    for src_func in helper_info:
        if "ret_type" not in helper_info[src_func]:
            continue

        ret = helper_info[src_func]["ret_type"]

        for dst_func in helper_info:
            if src_func == dst_func:
                continue
            for arg in helper_info[dst_func]:
                if re.search("arg[1-9]_type", arg):
                    for ret_sub in ret:
                        if ret_sub in helper_info[dst_func][arg]:
                            # pdb.set_trace()
                            arg_no = arg[3:-5]
                            if src_func not in graph:
                                graph[src_func] = list()
                            graph[src_func].append([dst_func, arg_no])
    return graph


"""
def filtered_graph(helpers, graph):
	
	sub_graph = dict()
	for helper in helpers:
		if helper in graph:
			for callee in graph[helper]:
				if callee in helpers:
					if helper not in sub_graph:
						sub_graph[helper] = list()
					sub_graph[helper].append(callee)
	return sub_graph
"""

def make_func_proto_hdr(filename, arrname, helper_info):
    with open(filename, "a") as f:
        f.write("#define MAX_" + arrname.upper() + "_ARR_SIZE " + str(len(helper_info)) + "\n")
        f.write(
                "const static struct {\n\tint funcName;\n\tbool gplOnly;\n\tint retTypeLength;\n\tconst char *retTypes[MAX_TYPE_SIZE];\n\tint argNum;\n\tstruct {\n\t\tint num;\n\t\tconst char *types[MAX_TYPE_SIZE];\n\t} argTypes[MAX_TYPE_SIZE];\n} " + arrname + "[MAX_" + arrname.upper() + "_ARR_SIZE] = {\n"
            )
        for _, i in helper_info.items():
            f.write("\t{\n\t\t" + i["func"] + ",\n\t\t")
            print(i["func"])
            # print(i["ret_type"])
            if "gpl_only" in i.keys():
                f.write(i["gpl_only"] + ",\n\t\t")
            else:
                f.write("false,\n\t\t")
            if "ret_type" in i.keys():
                if type(i["ret_type"][0]) == list and len(i["ret_type"][0]) > 2:
                    f.write(str(len(i["ret_type"][0])) + ",\n\t\t{")
                    for j in i["ret_type"][0]:
                        f.write('\n\t\t\t"')
                        if type(j) == list:
                            f.write(j[0] + '",\n\t\t\t')
                        else:
                            f.write(j + '",\n\t\t')
                    f.write("},\n\t\t")
                else:
                    f.write(str(len(i["ret_type"])) + ",\n\t\t{")
                    for j in i["ret_type"]:
                        f.write('\n\t\t\t"')
                        if type(j) == list:
                            f.write(j[0] + '",\n\t\t\t')
                        else:
                            f.write(j + '",\n\t\t')
                    f.write("},\n\t\t")
            else:
                f.write("0,\n\t\t{")
                f.write("},\n\t\t")
            if "arg5_type" in i.keys():
                argNum = 5
                f.write("5,\n\t\t")
            elif "arg4_type" in i.keys():
                argNum = 4
                f.write("4,\n\t\t")
            elif "arg3_type" in i.keys():
                argNum = 3
                f.write("3,\n\t\t")
            elif "arg2_type" in i.keys():
                argNum = 2
                f.write("2,\n\t\t")
            elif "arg1_type" in i.keys():
                argNum = 1
                f.write("1,\n\t\t")
            else:
                argNum = 0
                f.write("0,\n\t\t")
            f.write("{")
            for j in range(argNum):
                f.write("\n\t\t\t{\n\t\t\t\t")
                if (
                    type(i["arg" + str(j + 1) + "_type"]) != list
                    and type(i["arg" + str(j + 1) + "_type"]) != tuple
                ):
                    # print(i["arg" + str(j + 1) + "_type"])
                    f.write(
                        '1,\n\t\t\t\t{\n\t\t\t\t\t"'
                        + i["arg" + str(j + 1) + "_type"]
                        + '"\n\t\t\t\t}\n\t\t\t'
                    )
                elif (
                    type(i["arg" + str(j + 1) + "_type"][0]) == list
                    or type(i["arg" + str(j + 1) + "_type"][0]) == tuple
                ) and len(i["arg" + str(j + 1) + "_type"][0]) > 2:
                    f.write(
                        str(len(i["arg" + str(j + 1) + "_type"][0])) + ",\n\t\t\t\t{"
                    )
                    for k in i["arg" + str(j + 1) + "_type"][0]:
                        if type(k) == list:
                            f.write('\n\t\t\t\t\t"' + k[0] + '",')
                        else:
                            f.write('\n\t\t\t\t\t"' + k + '",')
                    f.write("\n\t\t\t\t},\n\t\t\t")
                else:
                    f.write(str(len(i["arg" + str(j + 1) + "_type"])) + ",\n\t\t\t\t{")
                    for k in i["arg" + str(j + 1) + "_type"]:
                        if type(k) == list:
                            f.write('\n\t\t\t\t\t"' + k[0] + '", ')
                        else:
                            f.write('\n\t\t\t\t\t"' + k + '",')
                    f.write("\n\t\t\t\t},\n\t\t\t")
                f.write("},")
            f.write("\n\t\t}\n\t")
            f.write("},\n")
        f.write("};\n\n")

def make_func_proto_hdr_ret(filename, arrname, helper_info):
    with open(filename, "a") as f:
        for ikey, ival in helper_info.items():
            f.write("#define MAX_" + ikey.upper() + "_" + arrname.upper() + "_ARR_SIZE " + str(len(ival)) + "\n")
            f.write(
                    "const static struct {\n\tint funcName;\n\tbool gplOnly;\n\tint retTypeLength;\n\tconst char *retTypes[MAX_TYPE_SIZE];\n\tint argNum;\n\tstruct {\n\t\tint num;\n\t\tconst char *types[MAX_TYPE_SIZE];\n\t} argTypes[MAX_TYPE_SIZE];\n} " + ikey + "_" + arrname + "[MAX_" + ikey.upper() + "_" + arrname.upper() + "_ARR_SIZE] = {\n"
                )
            for i in ival:
                f.write("\t{\n\t\t" + i["func"] + ",\n\t\t")
                print(i["func"])
                # print(i["ret_type"])
                if "gpl_only" in i.keys():
                    f.write(i["gpl_only"] + ",\n\t\t")
                else:
                    f.write("false,\n\t\t")
                if "ret_type" in i.keys():
                    if type(i["ret_type"][0]) == list and len(i["ret_type"][0]) > 2:
                        f.write(str(len(i["ret_type"][0])) + ",\n\t\t{")
                        for j in i["ret_type"][0]:
                            f.write('\n\t\t\t"')
                            if type(j) == list:
                                f.write(j[0] + '",\n\t\t\t')
                            else:
                                f.write(j + '",\n\t\t')
                        f.write("},\n\t\t")
                    else:
                        f.write(str(len(i["ret_type"])) + ",\n\t\t{")
                        for j in i["ret_type"]:
                            f.write('\n\t\t\t"')
                            if type(j) == list:
                                f.write(j[0] + '",\n\t\t\t')
                            else:
                                f.write(j + '",\n\t\t')
                        f.write("},\n\t\t")
                else:
                    f.write("0,\n\t\t{")
                    f.write("},\n\t\t")
                if "arg5_type" in i.keys():
                    argNum = 5
                    f.write("5,\n\t\t")
                elif "arg4_type" in i.keys():
                    argNum = 4
                    f.write("4,\n\t\t")
                elif "arg3_type" in i.keys():
                    argNum = 3
                    f.write("3,\n\t\t")
                elif "arg2_type" in i.keys():
                    argNum = 2
                    f.write("2,\n\t\t")
                elif "arg1_type" in i.keys():
                    argNum = 1
                    f.write("1,\n\t\t")
                else:
                    argNum = 0
                    f.write("0,\n\t\t")
                f.write("{")
                for j in range(argNum):
                    f.write("\n\t\t\t{\n\t\t\t\t")
                    if (
                        type(i["arg" + str(j + 1) + "_type"]) != list
                        and type(i["arg" + str(j + 1) + "_type"]) != tuple
                    ):
                        # print(i["arg" + str(j + 1) + "_type"])
                        f.write(
                            '1,\n\t\t\t\t{\n\t\t\t\t\t"'
                            + i["arg" + str(j + 1) + "_type"]
                            + '"\n\t\t\t\t}\n\t\t\t'
                        )
                    elif (
                        type(i["arg" + str(j + 1) + "_type"][0]) == list
                        or type(i["arg" + str(j + 1) + "_type"][0]) == tuple
                    ) and len(i["arg" + str(j + 1) + "_type"][0]) > 2:
                        f.write(
                            str(len(i["arg" + str(j + 1) + "_type"][0])) + ",\n\t\t\t\t{"
                        )
                        for k in i["arg" + str(j + 1) + "_type"][0]:
                            if type(k) == list:
                                f.write('\n\t\t\t\t\t"' + k[0] + '",')
                            else:
                                f.write('\n\t\t\t\t\t"' + k + '",')
                        f.write("\n\t\t\t\t},\n\t\t\t")
                    else:
                        f.write(str(len(i["arg" + str(j + 1) + "_type"])) + ",\n\t\t\t\t{")
                        for k in i["arg" + str(j + 1) + "_type"]:
                            if type(k) == list:
                                f.write('\n\t\t\t\t\t"' + k[0] + '", ')
                            else:
                                f.write('\n\t\t\t\t\t"' + k + '",')
                        f.write("\n\t\t\t\t},\n\t\t\t")
                    f.write("},")
                f.write("\n\t\t}\n\t")
                f.write("},\n")
            f.write("};\n\n")

if __name__ == "__main__":
    linux_src = sys.argv[1]
    ptype2callgraph = list()

    # build the relationship between these helper functions
    helper_info, indep_helpers, dep_helpers, ret_sort = extract_helper_info(linux_src)
    f = open("/usr/include/bpf/bpf_helper_defs.h")
    helper_enum = ["unspec"] + [re.findall("\(\*.*\)\(", i)[0][2:-2] for i in f.readlines() if i[:6] == "static"]
    f.close()
    helper_info = {k: i for k,i in helper_info.items() if i["func"] in helper_enum}
    indep_helpers = {k: i for k,i in indep_helpers.items() if i["func"] in helper_enum}
    dep_helpers = {k: i for k,i in dep_helpers.items() if i["func"] in helper_enum}
    for ikey, ival in ret_sort.items():
        ret_sort[ikey] = [j for j in ival if j["func"] in helper_enum]
    with open("./helper_proto.h", "w") as f:
        f.write("#define MAX_TYPE_SIZE 30\n")
        f.write("enum proto_addr {")
        for i in helper_enum:
            f.write("\n\t" + i + ",")
        f.write("\n};\n\n")
    make_func_proto_hdr("./helper_proto.h", "helper_proto", helper_info)
    make_func_proto_hdr("./helper_proto.h", "indep_helper_proto", indep_helpers)
    make_func_proto_hdr("./helper_proto.h", "dep_helper_proto", dep_helpers)
    make_func_proto_hdr_ret("./helper_proto.h", "ret", ret_sort)


    joj = set()
    for _, i in helper_info.items():
        if "ret_type" in i.keys():
            joj.add(i["ret_type"][0])
    print(joj)

    # print(helper_info)
    dataflow_graph = build_graph(helper_info)
    with open("./helper_dataflow.h", "w") as f:
        f.write("#define MAX_FLOW_ARR_SIZE 100\n")
        f.write(
            "const static struct {const char *str; struct { const char *s; int i; } attr[MAX_FLOW_ARR_SIZE]; int siz;} dataflowGraph[] = {"
        )
        # f.write(json.dumps(dataflow_graph))
        for i, j in dataflow_graph.items():
            f.write('{"')
            f.write(i)
            f.write('"')
            f.write(", {")
            for k in j:
                f.write('{"')
                f.write(k[0])
                f.write('"')
                f.write(", ")
                f.write(k[1])
                f.write("}, ")
            f.write("}, ")
            f.write(str(len(j)))
            f.write("},")
        f.write("};")

    # Progtype to get_func_proto suffix, like BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr
    progtype_helpers = dict()
    ptype2GFPsuffix = extractP2G(linux_src)
    with open("./progtypes.h", "w") as f:
        f.write("const char *progTypes[] = {")
        f.write(
            json.dumps(list(ptype2GFPsuffix.keys())).replace("[", "").replace("]", "")
        )
        f.write("};")

    for progtype in ptype2GFPsuffix:
        GPFsuffix = ptype2GFPsuffix[progtype]

        # e.g., cg_sock_addr to sock_addr_func_proto
        get_func_proto = ptype2get_func_proto(GPFsuffix, linux_src)
        print(get_func_proto)
        if get_func_proto == "":
            print("Can't find the .get_func_proto of {}".format(GPFsuffix))

        # get_func_proto to helper functions and their arg/return value types
        helpers = extract_related_helpers(linux_src, get_func_proto)
        progtype_helpers[progtype] = helpers
        # print(helpers)
        # generate the data flow graph for this prog type
        # sub_graph = filtered_graph(helpers, dataflow_graph)

    progs = ["BPF_PROG_TYPE_UNSPEC",
	'BPF_PROG_TYPE_SOCKET_FILTER',
	'BPF_PROG_TYPE_KPROBE',
	"BPF_PROG_TYPE_SCHED_CLS",
	"BPF_PROG_TYPE_SCHED_ACT",
	"BPF_PROG_TYPE_TRACEPOINT",
	"BPF_PROG_TYPE_XDP",
	"BPF_PROG_TYPE_PERF_EVENT",
	"BPF_PROG_TYPE_CGROUP_SKB",
	"BPF_PROG_TYPE_CGROUP_SOCK",
	"BPF_PROG_TYPE_LWT_IN",
	"BPF_PROG_TYPE_LWT_OUT",
	"BPF_PROG_TYPE_LWT_XMIT",
	"BPF_PROG_TYPE_SOCK_OPS",
	"BPF_PROG_TYPE_SK_SKB",
	"BPF_PROG_TYPE_CGROUP_DEVICE",
	"BPF_PROG_TYPE_SK_MSG",
	"BPF_PROG_TYPE_RAW_TRACEPOINT",
	"BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	"BPF_PROG_TYPE_LWT_SEG6LOCAL",
	"BPF_PROG_TYPE_LIRC_MODE2",
	"BPF_PROG_TYPE_SK_REUSEPORT",
	"BPF_PROG_TYPE_FLOW_DISSECTOR",
	"BPF_PROG_TYPE_CGROUP_SYSCTL",
	"BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	"BPF_PROG_TYPE_CGROUP_SOCKOPT",
	"BPF_PROG_TYPE_TRACING",
	"BPF_PROG_TYPE_STRUCT_OPS",
	"BPF_PROG_TYPE_EXT",
	"BPF_PROG_TYPE_LSM",
	"BPF_PROG_TYPE_SK_LOOKUP",
	"BPF_PROG_TYPE_SYSCALL",
	"BPF_PROG_TYPE_NETFILTER"]

    with open("./progtype_helpers.h", "w") as f:
        f.write('#include "helper_proto.h"\n')
        f.write('#include "linux/bpf.h"\n')
        f.write("#define MAX_ARR_SIZE 100\n")
        f.write(
            "const struct { int helpers[MAX_ARR_SIZE]; int siz; } progType2Helpers[] = {"
        )
        for i in progs:
            f.write('\n\t{\n\t\t{')
            print(progtype_helpers.get(i, []))
            siz_cnt = 0
            for j in progtype_helpers.get(i, []):
                if len(j) > 6 and (j[:-6] in helper_enum):
                    f.write("\n\t\t\t" + j[:-6] + ", ")
                    siz_cnt += 1
            f.write('\n\t\t},\n\t\t' + str(siz_cnt) + "\n\t},")
        f.write("\n};")
