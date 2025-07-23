
# ret value type -> arg type: compatible_reg_types

# prog_type -> get_func_proto name
# cat include/linux/bpf_types.h |grep "BPF_PROG_TYPE"|awk -F"[(,]" '{print $2,$3}'

list_helper_func_once() {
	srcdir=$1
	get_func_proto=$2
	pattern="^$get_func_proto(.*)$\|\*$get_func_proto(.*)$\|^$get_func_proto(.*,$\|\*$get_func_proto(.*,$"
	file=$(grep --include \*.c -rn $pattern $srcdir |awk -F":" '{print $1}')
    slno=$(grep --include \*.c -rn $pattern $srcdir |awk -F":" '{print $2}')
	#echo $get_func_proto, $file, $slno
    i=$slno
	helper_funcs=""
	for (( ; ; i++ ))
    do
        curline=$(cat $file|head -n $i|tail -n 1)
        if [ "$curline" == "}" ]; then
            break
        fi
        if [[ "$curline" == *return\ \&* ]]; then
			echo -e '\t'$(echo $curline|awk -F"&" '{print $2}'| awk -F";" '{print $1}')
			#helper_funcs=$helper_funcs"\n"$(echo $curline|awk -F"&" '{print $2}'| awk -F";" '{print $1}')
        fi
        if [[ "$curline" == *return\ [a-zA-Z]*proto*\(* ]]; then
			#echo -e $(echo $curline|awk '{print $2}'|awk -F"(" '{print $1}')
			list_helper_func_once $srcdir $(echo $curline|awk '{print $2}'|awk -F"(" '{print $1}')
			#echo $ret
			#helper_funcs=$helper_funcs"\n"$ret
		fi
    done
	#echo -e $helper_funcs
}

list_helper_func_of_one_prog_type(){
	grep -rn "\.get_func_proto" $1 |awk '{print $4}'|awk -F"," '{print $1}' | while read -r get_func_proto
	do
		echo $get_func_proto
		list_helper_func_once $1 $get_func_proto
		echo -e ''
	done
}

extract_helper_proto() {
	grep -rn  "struct bpf_func_proto .* = {" $1 | while read -r line
	do
		file=$(echo $line|awk -F":" '{print $1}')
		slno=$(echo $line|awk -F":" '{print $2}')
		#proto=$(cat $file|head -n $lno|tail -n 1|awk 'print {$4}')
		i=$slno
		for (( ; ; i++ ))
		do
			curline=$(cat $file|head -n $i|tail -n 1)
			if [ "$curline" == "};" ]
			then
				elno=$i
				break
			fi
		done
		cnt=$(( elno - slno + 1))
		cat $file|head -n $elno|tail -n $cnt
	done
}

prog_type2get_func_proto(){
	
}

cat $/include/linux/bpf_types.h | grep "BPF_PROG_TYPE"| while read -r prog2funcproto
do
	prog_type=$(echo $prog2funcproto|awk -F"[(,]" '{print $2}')
	suffix_get_func_proto=$(echo $prog2funcproto|awk -F"[(,]" '{print $3}')
	prog_type2get_func_proto $suffix_get_func_proto
	list_helper_func_of_one_prog_type $
done
