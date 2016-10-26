package org.raslin777.advancedLogging;

import android.content.Context;

import java.io.File;

import de.robv.android.xposed.XposedBridge;
import eu.chainfire.libsuperuser.Shell;

/**
 * Created by wmarino on 9/16/2016.
 */


class LaunchGCore implements Runnable {


    @Override
    public void run() {
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
        //XposedBridge.log("id=" + GcoreService.id2);

        //./gdb --pid="10580" --batch -ex "gcore /storage/4990-0B82/core"
        //for (int i = 0; i < 2; i++) {
            //Toast.makeText(MyReceiver.contextcore, "Detected PID " + MyReceiver.id + " going to gcore in 6 Seconds", Toast.LENGTH_LONG).show();
        //}


        try {
            //XposedBridge.log("Going to Sleep for 5000!");
            Thread.sleep(5000);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            //XposedBridge.log("No Sleep for you!!");
        }
        //try {

        //XposedBridge.log("Start Context Created!");
            Context contextcore2 = advancedLogging.context();
            //XposedBridge.log("End Context Created!");
            File[] fs = contextcore2.getExternalFilesDirs(null);
            String extPath = "";
            if (fs != null && fs.length >= 2) {
                //XposedBridge.log("Getting External Path!");
                extPath = fs[1].getAbsolutePath();
                //XposedBridge.log("SD Path "+ fs[1].getAbsolutePath());
            }
            String extPathDone = extPath;
            //XposedBridge.log(extPathDone);
            //String cmdlinestring = "busybox mount -o rw,remount /system\n/data/data/org.raslin777.advancedLogging/lib/libGdbX32modded.so --pid="+id+" --batch -ex \"gcore "+extPath+"/"+id+".core\"\n";
            String cmdlinestring = "/data/data/org.raslin777.advancedLogging/lib/libGdbX32modded.so --pid=" + GcoreService.id2 + " --batch -ex \"gcore " + extPath + "/" + GcoreService.id2 + ".core\" \n";
            //XposedBridge.log(cmdlinestring);
            //XposedBridge.log("Running Command!!");
            Shell.SU.run(cmdlinestring);
            //XposedBridge.log("Command ran!!!");
        /*
        } catch (Exception e) {
            //XposedBridge.log("Major Errors running GCore!!!!");
        }
        */
        // at index 0 you have the internal storage and at index 1 the real external...

        //for (int i = 0; i < 2; i++) {
            //Toast.makeText(MyReceiver.contextcore, "SDCARD == " + extPath, Toast.LENGTH_LONG).show();
        //}


    }
}