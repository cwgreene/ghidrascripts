package constants;

import java.util.HashMap;

public class SeccompConstants {
    static HashMap<Long, String> lookupActions;
	static {
        lookupActions = new HashMap<>();
		lookupActions.put(0L, "SCMP_ACT_KILL");
		lookupActions.put(0x80000000L, "SCMP_ACT_KILL_PROCESS");
        lookupActions.put(0x00030000L, "SCMP_ACT_TRAP");

        // These are high bits
		//lookupActions.put(0x00050000L, "SCMP_ACT_ERRNO");
        //lookupActions.put(0x7ff00000L, "SCMP_ACT_TRACE");

        lookupActions.put(0x7ffc0000L,"SCMP_ACT_LOG");
        lookupActions.put(0x7fff0000L,"SCMP_ACT_ALLOW");
        lookupActions.put(0x7fc00000L,"SCMP_ACT_NOTIFY");
    }

    static Long ErrnoPrefix = 0x00050000L;
    static Long TracePrefix = 0x7ff00000L;

    public static String actionToString(Long action) {
        if (lookupActions.containsKey(action)) {
            return lookupActions.get(action);
        }
        if ((action & ErrnoPrefix) == ErrnoPrefix) {
            long value = action ^ ErrnoPrefix;
            return "SCMP_ACT_ERRNO_"+value;
        }
        if ((action & TracePrefix) == TracePrefix) {
            long value = action ^ TracePrefix;
            return "SCMP_ACT_TRACE_"+value;
        }
        return "INVALID_ACTION_" + action;
    }
}