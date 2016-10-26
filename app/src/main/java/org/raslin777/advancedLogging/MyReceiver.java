package org.raslin777.advancedLogging;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.util.List;

import de.robv.android.xposed.XposedBridge;
import eu.chainfire.libsuperuser.Shell;

/**
 * Created by wmarino on 9/16/2016.
 */

public class MyReceiver extends BroadcastReceiver {
    public static Integer id;
    public static Integer coreint=0;
    public static Context contextcore;


    public boolean isCoreRunning() {

        Boolean flag = false;
        //ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        //List<ActivityManager.RunningAppProcessInfo> procInfos = activityManager.getRunningAppProcesses();
        //List<ProcessManager.Process> processes = ProcessManager.getRunningProcesses();
        List<String> stdout = Shell.SH.run("toolbox ps -p -P -x -c");
        for (String line : stdout) {
            Log.d("Running Processes", "()()"+line);
            if (line.contains("libGdbX32modded")) {
                //Toast.makeText(null, "gcore is running!!!", Toast.LENGTH_LONG).show();
                flag = true;
            }
        }
        return flag;
    }


    public void onReceive(Context context, Intent intent) {

            if (intent.getAction().equals("com.Raslin.Broadcast")) {
                coreint++;
                XposedBridge.log("Recevived Broadcast run is: " + coreint);
                if (coreint==1) {
                    XposedBridge.log("Broadcast Is Started!");
                    id = intent.getExtras().getInt("HookedPID");
                    contextcore = context;
                    XposedBridge.log("Running Thread");
                    LaunchGCore t1=new LaunchGCore();
                    t1.run();
                    XposedBridge.log("Broadcast Is done!");
                }
                else {
                    XposedBridge.log("Fuck your tring to run x" + coreint + "!");
                }
        }
    }
}