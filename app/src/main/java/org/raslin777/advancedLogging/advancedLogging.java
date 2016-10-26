package org.raslin777.advancedLogging;

import android.app.Application;
import android.content.Context;
import android.support.multidex.MultiDexApplication;

/**
 * Created by wmarino on 9/28/2016.
 */

public class advancedLogging extends MultiDexApplication {

    private static advancedLogging mCurrentInstance;

    @Override
    public void onCreate() {
        super.onCreate();

        mCurrentInstance = this;
    }


    public static advancedLogging instance() {
        return mCurrentInstance;
    }

    public static Context context() {
        return mCurrentInstance.getApplicationContext();
    }
}