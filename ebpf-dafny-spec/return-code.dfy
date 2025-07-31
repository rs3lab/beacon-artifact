include "types.dfy"

ghost predicate anyInitVal(r0:RegState, priv:bool)
    reads r0
    {
        r0.regType != UNINT && (!priv ==> r0.regType == SCALAR)
    }

ghost predicate scalarRange(r0:RegState, start:bv64, end:bv64)
    reads r0
    // [start, end], inclusive at both sides
    {
        r0.regType == SCALAR && start <= r0.regVal && r0.regVal <= end
    }

ghost predicate return_value_correct(r0:RegState, priv:bool, progType:ProgTypes, expected_attach_type:AttachTypes)
    reads r0
    {
        match progType {
            
            case BPF_PROG_TYPE_CGROUP_SKB => (
                if expected_attach_type == BPF_CGROUP_INET_EGRESS
                then scalarRange(r0, 0, 3)
                else scalarRange(r0, 0, 1)
            )

            case BPF_PROG_TYPE_CGROUP_SOCK =>
                scalarRange(r0, 0, 1)

            case BPF_PROG_TYPE_CGROUP_SOCK_ADDR => (
                (
                    if (expected_attach_type == BPF_CGROUP_UDP4_RECVMSG ||
                        expected_attach_type == BPF_CGROUP_UDP6_RECVMSG ||
                        expected_attach_type == BPF_CGROUP_UNIX_RECVMSG ||
                        expected_attach_type == BPF_CGROUP_INET4_GETPEERNAME ||
                        expected_attach_type == BPF_CGROUP_INET6_GETPEERNAME ||
                        expected_attach_type == BPF_CGROUP_UNIX_GETPEERNAME ||
                        expected_attach_type == BPF_CGROUP_INET4_GETSOCKNAME ||
                        expected_attach_type == BPF_CGROUP_INET6_GETSOCKNAME ||
                        expected_attach_type == BPF_CGROUP_UNIX_GETSOCKNAME
                    )
                        then scalarRange(r0, 1, 1)
                    else if (
                        expected_attach_type == BPF_CGROUP_INET4_BIND ||
                        expected_attach_type == BPF_CGROUP_INET6_BIND
                    )
                        then scalarRange(r0, 0, 3)
                    else
                        scalarRange(r0, 0, 1)
                )
            )

            case BPF_PROG_TYPE_SOCK_OPS => scalarRange(r0, 0, 1)

            /*
            TODO
            case BPF_PROG_TYPE_RAW_TRACEPOINT => (
                if (!env->prog->aux->attach_btf_id)
        	        return 0;
    	        range = retval_range(0, 0);
            )
            */

            case BPF_PROG_TYPE_TRACING => (
                if expected_attach_type == BPF_TRACE_FENTRY || expected_attach_type == BPF_TRACE_FEXIT
                    then scalarRange(r0, 0, 0)
                else if expected_attach_type == BPF_TRACE_RAW_TP || expected_attach_type == BPF_MODIFY_RETURN
                    then anyInitVal(r0, priv) // anything but not void
			    else if expected_attach_type == BPF_TRACE_ITER
                    then scalarRange(r0, 0, 1)
			    else false
            )

            case BPF_PROG_TYPE_CGROUP_DEVICE    => scalarRange(r0, 0, 1)
    		case BPF_PROG_TYPE_CGROUP_SYSCTL    => scalarRange(r0, 0, 1)
    	    case BPF_PROG_TYPE_CGROUP_SOCKOPT   => scalarRange(r0, 0, 1)
            case BPF_PROG_TYPE_SK_LOOKUP        => scalarRange(r0, 0, 1)

            /*
            TODO
            case BPF_PROG_TYPE_LSM => (
                if expected_attach_type == BPF_LSM_CGROUP then
			        if attached to void hooks then [1, 1] else [0, 1]
		        else
                    anyInitVal(r0, priv)
            )
            */

            case BPF_PROG_TYPE_NETFILTER => scalarRange(r0, 0, 1)

            case _ => anyInitVal(r0, priv) // Any initilized value (priv: scalar + ptr, unpriv:scalar)
        }
}