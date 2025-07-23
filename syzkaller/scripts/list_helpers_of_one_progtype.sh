list_helper_func_once() {
    srcdir=$1
    get_func_proto=$2
    pattern="^$get_func_proto(.*)$\|\*$get_func_proto(.*)$\|^$get_func_proto(.*,$\|\*$get_func_proto(.*,$"
    file=$(grep --include \*.c -rn $pattern $srcdir |head -n 1|awk -F":" '{print $1}')
    slno=$(grep --include \*.c -rn $pattern $srcdir |head -n 1|awk -F":" '{print $2}')
    echo $get_func_proto
    i=$slno
    helper_funcs=""
	for (( ; ; i++ ))
	do
		curline=$(cat $file|head -n $i|tail -n 1)
		if [ "$curline" == "}" ]; then
			break
        fi
        if [[ "$curline" == *return\ \&* ]]; then
            echo -e $(echo $curline|awk -F"&" '{print $2}'| awk -F";" '{print $1}')
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

list_helper_func_once $1 $2
