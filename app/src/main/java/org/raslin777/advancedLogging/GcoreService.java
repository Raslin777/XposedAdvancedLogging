package org.raslin777.advancedLogging;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import de.robv.android.xposed.XposedBridge;

/**
 * Created by wmarino on 9/28/2016.
 */

public class GcoreService extends Service {
    public static Integer id2;
    public static Integer coreint2=0;
    public static Thread performOnBackgroundThread(final Runnable runnable) {
        final Thread t = new Thread() {
            @Override
            public void run() {
                try {
                    runnable.run();
                } finally {
                }
            }
        };
        t.start();
        return t;
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        //TODO gcore Service Recivier
        coreint2++;
            //XposedBridge.log("Recevived Service run is: " + coreint2);
            if (coreint2==1) {
                //XposedBridge.log("Service Is Started!");
                id2 = intent.getExtras().getInt("HookedPID");
                //XposedBridge.log("Running Thread");
                LaunchGCore t1=new LaunchGCore();
                performOnBackgroundThread(t1);
                //XposedBridge.log("Service Is done!");
            }
            else {
                //XposedBridge.log("Fuck your tring to run x" + coreint2 + "!");
            }
        return Service.START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        //XposedBridge.log("BIND WAS CALLED!!");
        return null;
    }
    public void onDestroy() {
        super.onDestroy();
        //XposedBridge.log("Service Ended!!");
    }
}