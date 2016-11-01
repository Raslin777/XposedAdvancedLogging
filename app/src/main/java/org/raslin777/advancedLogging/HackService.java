package org.raslin777.advancedLogging;

import android.app.AndroidAppHelper;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import java.net.Socket;

import java.security.SecureRandom;
import java.security.KeyStore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import eu.chainfire.libsuperuser.Shell;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XSharedPreferences;
import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.newInstance;
import static de.robv.android.xposed.XposedHelpers.setObjectField;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.ssl.SSLSocketFactory;

public class HackService implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    //	private static final String TAG = HackService.class.getSimpleName();
    public int oneshot = 0;
    private XSharedPreferences prefs;
    static String libPath = "/data/data/org.raslin777.advancedLogging/lib/";

    //private static final String[] CLASSES_TO_HOOKS = {};
    @Override
    public void initZygote(IXposedHookZygoteInit.StartupParam paramStartupParam) throws Throwable {
        loadPrefs();
    }
    private static void log(String string) {
        /* Simulate XposedBridge.log, this way we don't rape I/O */
        Log.w("Xposed", String.format("%s: %s", "advancedLogging", string));
    }
    private void loadPrefs() {
        prefs = new XSharedPreferences(Common.MY_PACKAGE_NAME, "ModSettings");
        //prefs.makeWorldReadable();
    }


    @SuppressWarnings("rawtypes")
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        prefs.reload();

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN SSLPINNING
        // TODO SSLPINNING TESTING
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/BypassSSL", false)) { //HOOK FOR DebugDex        XposedBridge.log("Xposed SSLUnpinning: " + packageName);

            // --- Java Secure Socket Extension (JSSE) ---
            try {
                findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XC_MethodHook() {

                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                        TrustManager[] tms = EmptyTrustManager.getInstance();
                        param.setResult(tms);
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }
            //SSLContext.init >> (null,EmptyTrustManager,null)
            try {
                findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", KeyManager[].class, TrustManager[].class, SecureRandom.class, new XC_MethodHook() {

                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[0] = null;
                        param.args[1] = EmptyTrustManager.getInstance();
                        param.args[2] = null;
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }
            //HttpsURLConnection.setSSLSocketFactory >> new SSLSocketFactory
            try {
                findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", javax.net.ssl.SSLSocketFactory.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[0] = newInstance(javax.net.ssl.SSLSocketFactory.class);
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }
            // --- APACHE ---

            //HttpsURLConnection.setDefaultHostnameVerifier >> SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
            try {
                findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier",
                        HostnameVerifier.class, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.args[0] = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                            }
                        });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }
            //HttpsURLConnection.setHostnameVerifier >> SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
            try {
                findAndHookMethod("org.apache.http.conn.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", HostnameVerifier.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.args[0] = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                            }
                        });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }

            //SSLSocketFactory.getSocketFactory >> new SSLSocketFactory
            try {
                findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "getSocketFactory", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult((SSLSocketFactory) newInstance(SSLSocketFactory.class));
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }

            //SSLSocketFactory(...) >> SSLSocketFactory(...){ new EmptyTrustManager()}
            try {
                Class <?> sslSocketFactory = findClass("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader);
                findAndHookConstructor(sslSocketFactory, String.class, KeyStore.class, String.class, KeyStore.class,
                        SecureRandom.class, HostNameResolver.class, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                                String algorithm = (String) param.args[0];
                                KeyStore keystore = (KeyStore) param.args[1];
                                String keystorePassword = (String) param.args[2];
                                SecureRandom random = (SecureRandom) param.args[4];

                                KeyManager[] keymanagers = null;
                                TrustManager[] trustmanagers;

                                if (keystore != null) {
                                    keymanagers = (KeyManager[]) callStaticMethod(SSLSocketFactory.class, "createKeyManagers", keystore, keystorePassword);
                                }

                                trustmanagers = new TrustManager[] {
                                        new EmptyTrustManager()
                                };

                                setObjectField(param.thisObject, "sslcontext", SSLContext.getInstance(algorithm));
                                callMethod(getObjectField(param.thisObject, "sslcontext"), "init", keymanagers, trustmanagers, random);
                                setObjectField(param.thisObject, "socketfactory", callMethod(getObjectField(param.thisObject, "sslcontext"), "getSocketFactory"));
                            }

                        });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }

            //SSLSocketFactory.isSecure >> true
            try {
                findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", Socket.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(true);
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }

            ///OKHTTP
            try {
                findAndHookMethod("okhttp3.CertificatePinner", lpparam.classLoader, "findMatchingPins", String.class, new XC_MethodHook() {
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.args[0] = "";
                    }
                });
            } catch (Error e) {
                XposedBridge.log("Unpinning_error: " + e.getMessage());
            }


        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END SSLPINNING
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // TODO PermissionsInjections TESTING
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getString("AndroidNativeSave" + "/PermissionsInject", "").length() > 0) {
            String injectnames = (prefs.getString("AndroidNativeSave" + "/PermissionsInject", ""));
            final String[] Strings1;
            String delimiter = "\n";
            Strings1 = injectnames.split(delimiter);


            if (lpparam.packageName.equals("android")) {
                //final Class<?> pmServiceClass = XposedHelpers.findClass("com.android.server.pm.PackageManagerService", null);
                final Class <?> pmServiceClass = findClass("com.android.server.pm.PackageManagerService", lpparam.classLoader);
                /*
                    Scanner scc = new Scanner(new File("/data/data/org.raslin777.advancedLogging/writeperm.txt"));
                    List<String> liness = new ArrayList<String>();
                    while (scc.hasNextLine()) {
                        liness.add(scc.nextLine());
                    }

                    final String[] Strings1 = liness.toArray(new String[liness.size()]);
                 */

                XC_MethodHook hookGrantPermissions = new XC_MethodHook() {
                    @Override

                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                        //ThreadLocal<Map<String, Integer>> mRestoreInfo = new ThreadLocal<Map<String, Integer>>() {
                        //    protected Map<String, Integer> initialValue() { return new HashMap<String, Integer>(); }
                        //};

                        final String pkgName = (String) getObjectField(param.args[0], "packageName");
                        //XposedBridge.log("Inside: grantPermissionsLPw");
                        for (String name: Strings1) {
                            if (name.equals(pkgName)) {
                                XposedBridge.log("Inside: grantPermissionsLPw = found package:" + name);

                                ArrayList < String > origRequestedPermissions = (ArrayList < String > ) getObjectField(param.args[0], "requestedPermissions");
                                XposedBridge.log("Got object requestedPermissions");
                                param.setObjectExtra("orig_requested_permissions", origRequestedPermissions);
                                ArrayList < String > newRequestedPermissions = new ArrayList < String > (origRequestedPermissions.size());
                                String injperm = "android.permission.WRITE_EXTERNAL_STORAGE";
                                List < String > injperms = new ArrayList < String > ();
                                if (prefs.getString("AndroidNativeSave" + "/PermissionsAdd", "").length() > 0) {
                                    String injectperm = (prefs.getString("AndroidNativeSave" + "/PermissionsAdd", ""));
                                    String[] Strings2;
                                    String delimiter = "\n";
                                    Strings2 = injectperm.split(delimiter);
                                    injperms = Arrays.asList(Strings2);
                                } else {
                                    injperms.add(injperm);
                                }

                                for (String perm: origRequestedPermissions) {
                                    if (!injperms.contains(perm))
                                        newRequestedPermissions.add(perm);
                                }
                                for (String perminect: injperms) {
                                    XposedBridge.log("Injecting permission " + perminect);
                                    newRequestedPermissions.add(perminect);
                                }


                                XposedBridge.log("Setting Injection");
                                setObjectField(param.args[0], "requestedPermissions", newRequestedPermissions);
                                XposedBridge.log("Completed Injection");

                                ////////////////////////////////////////////////////////////////////////////////////////////
                                /*
                                        Object extras = getObjectField(param.args[0], "mExtras");
                                        Set<String> grantedPerms = (Set<String>) getObjectField(extras, "grantedPermissions");
                                        Object sharedUser = getObjectField(extras, "sharedUser");
                                        if (sharedUser != null)
                                            grantedPerms = (Set<String>) getObjectField(sharedUser, "grantedPermissions");
                                        Object settings = getObjectField(param.thisObject, "mSettings");
                                        Object permissions = getObjectField(settings, "mPermissions");

/*
                                // Add android.permission.WRITE_EXTERNAL_STORAGE to application
                                if (!grantedPerms.contains("android.permission.WRITE_EXTERNAL_STORAGE")) {
                                    XposedBridge.log("Inside: grantPermissionsLPw = adding Write External");
                                    final Object pAccessBroadcastMedia = callMethod(permissions, "get",
                                            "android.permission.WRITE_EXTERNAL_STORAGE");
                                    grantedPerms.add("android.permission.WRITE_EXTERNAL_STORAGE");
                                    int[] gpGids = (int[]) getObjectField(extras, "gids");
                                    int[] bpGids = (int[]) getObjectField(pAccessBroadcastMedia, "gids");
                                    gpGids = (int[]) callStaticMethod(param.thisObject.getClass(),
                                            "appendInts", gpGids, bpGids);
*/
                                /*
                                                                        if (prefs.getString("AndroidNativeSave" + "/PermissionsAdd", "").length() > 0) {
                                                                            String injectperm = (prefs.getString("AndroidNativeSave" + "/PermissionsAdd", ""));
                                                                            String[] Strings2;
                                                                            String delimiter = "\n";
                                                                            Strings2 = injectperm.split(delimiter);

                                                                            //String perm = "android.permission.WRITE_EXTERNAL_STORAGE";
                                                                            for (String perm : Strings2) {
                                                                                Object permission = callMethod(permissions, "get", perm);
                                                                                grantedPerms.add(perm);
                                                                                int[] gpGids = (int[]) getObjectField(sharedUser != null ? sharedUser : extras, "gids");
                                                                                int[] bpGids = (int[]) getObjectField(permission, "gids");
                                                                                callStaticMethod(param.thisObject.getClass(),
                                                                                        "appendInts", gpGids, bpGids);
                                                                                XposedBridge.log("Permission added: " + permission);
                                                                            }
                                                                        } else {
                                                                            String perm = "android.permission.WRITE_EXTERNAL_STORAGE";

                                                                            Object permission = callMethod(permissions, "get", perm);
                                                                            grantedPerms.add(perm);
                                                                            int[] gpGids = (int[]) getObjectField(sharedUser != null ? sharedUser : extras, "gids");
                                                                            int[] bpGids = (int[]) getObjectField(permission, "gids");
                                                                            callStaticMethod(param.thisObject.getClass(),
                                                                                    "appendInts", gpGids, bpGids);
                                                                            XposedBridge.log("Permission added: " + perm);

                                                                        }
                                                                        */
                            }
                        }
                    }
                };

                //XposedBridge.log("Inside: grantPermissionsLPw = Complete");
                if (Build.VERSION.SDK_INT < 21) {
                    findAndHookMethod(pmServiceClass, "grantPermissionsLPw", "android.content.pm.PackageParser$Package", boolean.class, hookGrantPermissions);
                } else {
                    findAndHookMethod(pmServiceClass, "grantPermissionsLPw", "android.content.pm.PackageParser$Package", boolean.class, String.class, hookGrantPermissions);
                }
            }
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN DebugAllApps
        // TODO ZZZZZDebugAllApps Working
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean("AndroidNativeSave" + "/DebugDex", false)) { //HOOK FOR DebugDex
            //final boolean debugApps = true;
            if (lpparam.packageName.equals("android") &&
                    lpparam.processName.equals("android")) {
                XposedBridge.log(lpparam.packageName + ":Hook is called");
                Class <?> process = XposedHelpers.findClass(
                        "android.os.Process", null);
                XposedBridge.hookAllMethods(process, "start", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        int DEBUG_ENABLE_DEBUGGER = 0x1;
                        int id = 5;
                        int flags = (Integer) param.args[id];

                        //XposedBridge.log(lpparam.packageName + "flags is called");

                        //if (debugApps) {
                        //if ((flags & DEBUG_ENABLE_DEBUGGER) == 0) {
                        flags |= DEBUG_ENABLE_DEBUGGER;
                        //}
                        //}

                        param.args[id] = flags;
                        //XposedBridge.log(lpparam.packageName + "flags changed");

                    }
                });
            }
            //Enables all applications in the settings debugging list.
            if (lpparam.packageName.equals("com.android.settings")) {
                XposedBridge.log("Setting Build.TYPE userdebug");
                XposedHelpers.setStaticObjectField(Build.class, "TYPE",
                        "userdebug");
            }
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END DebugAllApps
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN UNITY REDIRECT
        // TODO UNITY REDIRECT Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/PackagePathRedirect", false)) { //HOOK FOR UNITY/APPCHECK REDIRECT
            findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader, "getPackageCodePath", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("Inside getPackageCodePath Hook");
                    String sLib2 = (String) param.getResult();
                    XposedBridge.log("getPackageCodePath is " + sLib2);

                    param.setResult("/mnt/sdcard/" + lpparam.packageName + "/pkg.apk");
                    XposedBridge.log("Changed getPackageCodePath Hook");
                    sLib2 = (String) param.getResult();
                    XposedBridge.log("getPackageCodePath is now " + sLib2);

                }
            });

        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END UNITY REDIRECT
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN GCORE
        // ;TODO ZZZZZGCORE Working
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/CreateGcore", false)) { //Need to find a better hook for dump // Need to change name...
            //final String LibToHook = (prefs.getString(lpparam.packageName + "/CreateGcore", ""));
            XposedBridge.log("App was launched and we are going to gcore!");
            // WE NEED ALERT!



            /*
            //int id = 0;
            findAndHookMethod("java.lang.ClassLoader", lpparam.classLoader, "loadClass", String.class, new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Integer ids= android.os.Process.myPid();
                    String IDStringInt = Integer.toString(ids);
                        try {
                            File file = new File("/data/data/"+lpparam.packageName+"/myfilepid.txt");
                            file.delete();
                            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/data/data/"+lpparam.packageName+"/myfilepid.txt", true)));
                            out.println(IDStringInt);
                            out.close();
                        } catch (IOException e) {
                            //exception handling left as an exercise for the reader
                        }

                }

            });

            Scanner sc = new Scanner(new File("/data/data/"+lpparam.packageName+"/myfilepid.txt"));
            String id = "";
            id = sc.nextLine();

            XposedBridge.log("App was launched and we have PID:"+id);
            Thread.sleep(15000);
            XposedBridge.log("Sleeping over!");

            //./gdb --pid="10580" --batch -ex "gcore /storage/4990-0B82/core"

            Runtime.getRuntime().exec("su -c ./data/data/org.raslin777.advancedLogging/gdb --pid="+id+" --batch -ex gcore");
            XposedBridge.log("Gcore over!");

            String cmdlinestring = "./data/temp/gdb --pid="+id+" --batch -ex gcore\n";
            Process p;
            try {
                // Preform su to get root privledges
                p = Runtime.getRuntime().exec("su");

                // Attempt to write a file to a root-only
                DataOutputStream os = new DataOutputStream(p.getOutputStream());
                os.writeBytes(cmdlinestring);

                // Close the terminal
                os.writeBytes("exit\n");
                os.flush();
                try {
                    p.waitFor();
                    if (p.exitValue() != 255) {
                        //toastMessage("root");
                        //return true;
                    } else {
                        //toastMessage("not root");
                    }
                } catch (InterruptedException e) {
                    //toastMessage("not root");
                }
            } catch (IOException e) {
               // toastMessage("not root");
            }
            */



            findAndHookMethod("java.lang.ClassLoader", lpparam.classLoader, "loadClass", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                    String sLib = (String) param.args[0];
                    XposedBridge.log(sLib);
                    if (sLib.contains("Activity")) {
                        XposedBridge.log("Found the class " + sLib + " going to try dump!");
                        //This is android-unpacker
                        //Runtime.getRuntime().exec("su -c ./data/data/"+lpparam.packageName+"/kisskiss " + lpparam.packageName);
                        //

                        /*OLD Broadcast Intent
                        int id= android.os.Process.myPid();
                        Context context = AndroidAppHelper.currentApplication();
                        Intent intent = new Intent();
                        intent.setAction("com.Raslin.Broadcast");
                        intent.putExtra("HookedPID", id);
                        context.sendBroadcast(intent);
                        */
                        //This will create gcore. GDB must be in /system/bin
                        int id = android.os.Process.myPid();

                        final Context context = AndroidAppHelper.currentApplication();
                        Intent intent = new Intent("org.raslin777.advancedLogging.GcoreService.START_SERVICE");
                        intent.setPackage("org.raslin777.advancedLogging");
                        intent.putExtra("HookedPID", id);
                        context.startService(intent);
                        XposedBridge.log("Xposed Is done with GCore!");
                        //Future...?
                        //This will dump memory segments, gdb must be in system/bin // need to edit script to add memory object //pid-startaddress-stopaddress.dump
                        //int id= android.os.Process.myPid();
                        //final Process pr = Runtime.getRuntime().exec("su -c ./data/temp/test.sh "+id);
                        //pr.getInputStream();
                        //
                    }


                }

            });


            // Hooks the Runtime.exec() method. This is the only one that needs to be hooked because the other two versions of exec() just end up calling this one.
            /*
            findAndHookMethod("dalvik.system.DexFile", lpparam.classLoader, "loadClass", String.class, ClassLoader.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                    String sLib = (String) param.args[0];
                    XposedBridge.log(sLib);
                    if (sLib.contains("Activity")) {
                        XposedBridge.log("Found the "+LibToHook+" going to try dump!");
                        //This is android-unpacker
                        //Runtime.getRuntime().exec("su -c ./data/data/"+lpparam.packageName+"/kisskiss " + lpparam.packageName);
                        //

                        //This will create gcore.
                        //int id= android.os.Process.myPid();
                        //Runtime.getRuntime().exec("su -c ./data/temp/gdb --pid="+id+" --batch -ex gcore");
                        //XposedBridge.log("Dump complete, check SU for errors!");
                        //This will dump memory segments, gdb must be in system/bin // need to edit script to add memory object //pid-startaddress-stopaddress.dump
                        int id= android.os.Process.myPid();
                        String cmdlinestring = "./data/data/"+lpparam.packageName+"/gdb --pid="+id+" --batch -ex gcore\n";
                        Process p;
                        try {
                            // Preform su to get root privledges
                            p = Runtime.getRuntime().exec("su");

                            // Attempt to write a file to a root-only
                            DataOutputStream os = new DataOutputStream(p.getOutputStream());
                            os.writeBytes(cmdlinestring);

                            // Close the terminal
                            os.writeBytes("exit\n");
                            os.flush();
                            try {
                                p.waitFor();
                                if (p.exitValue() != 255) {
                                    //toastMessage("root");
                                    //return true;
                                } else {
                                    //toastMessage("not root");
                                }
                            } catch (InterruptedException e) {
                                //toastMessage("not root");
                            }
                        } catch (IOException e) {
                            // toastMessage("not root");
                        }
                    //
                    }
                }

            });
            */


        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END GCORE
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN DUMPDEX
        // TODO ZZZZZDUMPDEX Working Need Text Change
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/DumpDexFile", false)) { //DUMP DEX FUNCTION

            XposedHelpers.findAndHookConstructor("dalvik.system.BaseDexClassLoader", lpparam.classLoader, String.class, File.class, String.class, ClassLoader.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String outDir = "/data/data/" + lpparam.packageName;
                    String dexPath = (String) param.args[0];
                    String libraryPath = (String) param.args[2];

                    //Ignore loading of files from /system, comment this out if you wish
                    if (dexPath.startsWith("/system/"))
                        return;

                    XposedBridge.log("Hooking dalvik.system.BaseDexClassLoader for " + lpparam.packageName);
                    String uniq = UUID.randomUUID().toString();
                    outDir = outDir + "/" + lpparam.packageName + "-DEX-" + uniq;
                    XposedBridge.log("Capturing DEX:" + dexPath);
                    XposedBridge.log("Writing DEX to:" + outDir);
                    XposedBridge.log("Lib Path is:" + libraryPath);

                    //DEX DUMP
                    InputStream in = new FileInputStream(dexPath);
                    OutputStream out = new FileOutputStream(outDir);
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = in .read(buf)) > 0) {
                        out.write(buf, 0, len);
                    } in .close();
                    out.close();
                }
                @Override
                protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) throws Throwable {}
            });

            findAndHookMethod("dalvik.system.DexFile", lpparam.classLoader, "openDexFile", String.class, String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String outDir2 = "/data/data/" + lpparam.packageName;
                    String dexPath2 = (String) param.args[0];

                    //Ignore loading of files from /system, comment this out if you wish
                    if (dexPath2.startsWith("/system/"))
                        return;

                    XposedBridge.log("Hooking dalvik.system.DexFile for " + lpparam.packageName);
                    String uniq = UUID.randomUUID().toString();
                    outDir2 = outDir2 + "/" + lpparam.packageName + "-DEX2-" + uniq;

                    XposedBridge.log("Capturing " + dexPath2);
                    XposedBridge.log("Writing to " + outDir2);

                    InputStream in2 = new FileInputStream(dexPath2);
                    OutputStream out2 = new FileOutputStream(outDir2);
                    byte[] buf2 = new byte[1024];
                    int len2;
                    while ((len2 = in2.read(buf2)) > 0) {
                        out2.write(buf2, 0, len2);
                    }
                    in2.close();
                    out2.close();
                }
            });

            findAndHookMethod("dalvik.system.DexFile", lpparam.classLoader, "loadDex", String.class, String.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String outDir3 = "/data/data/" + lpparam.packageName;
                    String dexPath3 = (String) param.args[0];

                    //Ignore loading of files from /system, comment this out if you wish
                    if (dexPath3.startsWith("/system/"))
                        return;

                    XposedBridge.log("Hooking dalvik.system.DexFile for " + lpparam.packageName);
                    String uniq = UUID.randomUUID().toString();
                    outDir3 = outDir3 + "/" + lpparam.packageName + "-DEX3-" + uniq;

                    XposedBridge.log("Capturing " + dexPath3);
                    XposedBridge.log("Writing to " + outDir3);

                    InputStream in3 = new FileInputStream(dexPath3);
                    OutputStream out3 = new FileOutputStream(outDir3);
                    byte[] buf3 = new byte[1024];
                    int len3;
                    while ((len3 = in3.read(buf3)) > 0) {
                        out3.write(buf3, 0, len3);
                    }
                    in3.close();
                    out3.close();
                }
            });
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END DUMPDEX
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN LogAllClasses
        // TODO ZZZZZLogAllClasses Partial Working
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/LogAllClasses", false)) { //HOOK ALL CLASSES
            findAndHookMethod("java.lang.ClassLoader", lpparam.classLoader, "loadClass", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String sLib = (String) param.args[0];
                    XposedBridge.log(sLib);

                    if (prefs.getString(lpparam.packageName + "/GrepClass", "").length() > 0) {
                        final String GrepInfo = (prefs.getString(lpparam.packageName + "/GrepClass", ""));
                        //XposedBridge.log(GrepInfo);
                        if (sLib.indexOf(GrepInfo) >= 0) {
                            try {
                                PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/data/data/" + lpparam.packageName + "/myfile.txt", true)));
                                out.println(sLib);
                                out.close();
                            } catch (IOException e) {}
                        }
                    } else {
                        try {
                            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/data/data/" + lpparam.packageName + "/myfile.txt", true)));
                            out.println(sLib);
                            out.close();
                        } catch (IOException e) {}

                    }

                }
            });
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END LogAllClasses
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN MethodRedirect
        // TODO ZZZZZMethodRedirect Partial Working
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/MethodRedirect", false)) {

            Scanner sc = new Scanner(new File("/data/data/org.raslin777.advancedLogging/classes.txt"));
            final List < String > CLASSES_TO_HOOK = new ArrayList < String > ();
            while (sc.hasNextLine()) {
                CLASSES_TO_HOOK.add(sc.nextLine());
            }

            /* Generic hook for all the methods */
            final ArrayList < String > ar1 = new ArrayList < String > ();
            findAndHookMethod("java.lang.ClassLoader", lpparam.classLoader, "loadClass", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                    XC_MethodHook hook = new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            String paramTypesReturn = "";
                            String paramTypes = "";
                            int paramlenths = 0;
                            if (param.args != null) {
                                paramlenths = param.args.length;
                                if (param.args.length > 0) {
                                    for (Object arg: param.args) {
                                        String paramValue = null;
                                        if (arg instanceof java.lang.Boolean) {
                                            Boolean paramBool = (Boolean) arg;
                                            paramValue = String.valueOf(paramBool);
                                        } else if (arg instanceof String) {
                                            paramValue = (String) arg;
                                        } else if (arg instanceof Integer) {
                                            Integer paramInteger = (Integer) arg;
                                            paramValue = String.valueOf(paramInteger);
                                        } else if (arg instanceof Float) {
                                            Float paramFloat = (Float) arg;
                                            paramValue = String.valueOf(paramFloat);
                                        } else if (arg instanceof Long) {
                                            Long paramLong = (Long) arg;
                                            paramValue = String.valueOf(paramLong);
                                        } else if (arg instanceof String[]) {
                                            String[] paramValueSArray;
                                            paramValueSArray = (String[]) arg;
                                            log(String.format("Param of next method is String Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XSX";
                                        } else if (arg instanceof byte[]) {
                                            byte[] paramValueSArray;
                                            paramValueSArray = (byte[]) arg;
                                            log(String.format("Param of next method is byte Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XBX";
                                        } else if (arg instanceof int[]) {
                                            int[] paramValueSArray;
                                            paramValueSArray = (int[]) arg;
                                            log(String.format("Param of next method is int Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XIX";
                                        } else if (arg instanceof long[]) {
                                            long[] paramValueSArray;
                                            paramValueSArray = (long[]) arg;
                                            log(String.format("Param of next method is long Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XLX";
                                        } else if (arg instanceof float[]) {
                                            float[] paramValueSArray;
                                            paramValueSArray = (float[]) arg;
                                            log(String.format("Param of next method is float Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XFX";
                                        } else if (arg instanceof double[]) {
                                            double[] paramValueSArray;
                                            paramValueSArray = (double[]) arg;
                                            log(String.format("Param of next method is double Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XDX";
                                        } else if (arg instanceof char[]) {
                                            char[] paramValueSArray;
                                            paramValueSArray = (char[]) arg;
                                            log(String.format("Param of next method is char Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XCX";
                                        } else if (arg instanceof boolean[]) {
                                            boolean[] paramValueSArray;
                                            paramValueSArray = (boolean[]) arg;
                                            log(String.format("Param of next method is boolean Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XBX";
                                        } else if (arg instanceof byte[]) {
                                            byte[] paramValueSArray;
                                            paramValueSArray = (byte[]) arg;
                                            log(String.format("Param of next method is byte Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XbX";
                                        } else if (arg == null) {
                                            paramValue = "NULL";
                                        } else {
                                            Object tmpObject = null;
                                            String redisString = "";
                                            String serializedObject = "";
                                            String Base64Object = "";
                                            try {

                                                tmpObject = arg;
                                                if (tmpObject == null) {
                                                    paramValue = "NULL";
                                                }

                                                /*
                                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                                ObjectOutputStream oos = new ObjectOutputStream( baos );
                                                oos.writeObject(tmpObject);
                                                oos.close();
                                                Base64Object = Base64.encode(baos.toByteArray(),Base64.DEFAULT).toString();
                                                log(String.format("Param of next method is Object Array[Base64]: %s", Base64Object));
                                                */

                                                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                                                ObjectOutputStream so = new ObjectOutputStream(bo);
                                                so.writeObject(tmpObject);
                                                so.flush();
                                                serializedObject = bo.toString();
                                                //paramValueObject = tmpObject.toString();
                                                log(String.format("Param of next method is Object Array: %s", arg.toString()));
                                                log(String.format("Object Array DUMP: %s", serializedObject));
                                                paramValue = "XOX";
                                            } catch (Throwable ex) {
                                                paramValue = arg.toString();
                                            }
                                        }


                                        if (paramValue != null)
                                            paramTypes += " " + paramValue + " |=|";

                                    }
                                }
                            }

                            if (param.getResult() != null) {

                                String str1 = param.getResult().toString();
                                String str2 = "[B@";
                                String str3 = "[Ljava.lang.String;@";
                                String paramValueReturn = null;

                                if (param.getResult() instanceof java.lang.Boolean) {
                                    Boolean paramBool = (Boolean) param.getResult();
                                    paramValueReturn = String.valueOf(paramBool);
                                }
                                if (param.getResult() instanceof String) {
                                    paramValueReturn = (String) param.getResult();
                                }
                                if (str1.toLowerCase().contains(str3.toLowerCase())) {
                                    String[] paramValueSArray;
                                    paramValueSArray = (String[]) param.getResult();
                                    log(String.format("Return of next method is String Array: %s", (Arrays.toString(paramValueSArray))));
                                }
                                if (paramValueReturn != null)
                                    paramTypesReturn += paramValueReturn + ";";
                                else {
                                    try {
                                        paramTypesReturn += param.getResult().toString();
                                    } catch (Throwable ex) {
                                        paramTypesReturn += "CannotCastToString;";
                                    }
                                }
                                // Needs cleanup
                                if (str1.toLowerCase().contains(str2.toLowerCase())) {
                                    char[] hexArray = "0123456789ABCDEF".toCharArray();
                                    byte[] bytes = (byte[]) param.getResult();
                                    char[] hexChars = new char[bytes.length * 2];

                                    for (int j = 0; j < bytes.length; j++) {
                                        int v = bytes[j] & 0xFF;
                                        hexChars[j * 2] = hexArray[v >>> 4];
                                        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
                                    }
                                    String Decryted = new String(hexChars);
                                    paramTypesReturn = "Decrypted with return of: " + Decryted;
                                    log(String.format("Decrypted with return of: %s", Decryted));
                                    if (prefs.getBoolean(lpparam.packageName + "/DecodeHex", false)) {

                                        String hex = Decryted;
                                        String ascii = "";
                                        for (int i = 0; i < hex.length() - 1; i += 2) {

                                            //split the hex into pairs
                                            String pair = hex.substring(i, (i + 2));
                                            //convert hex to decimal
                                            int dec = Integer.parseInt(pair, 16);
                                            //convert the decimal to character
                                            String str;
                                            str = Character.toString((char) dec);

                                            if (dec < 32 || dec > 126 && dec < 161)
                                                str = "|";

                                            ascii = ascii + " " + str;
                                        }

                                        log(String.format("Decrypted with ascii return of: %s", ascii));
                                    }
                                }

                            } else {
                                paramTypesReturn += "NULL;";
                            }

                            if (param.thisObject == null) {
                                if (param.getResult() != null) {
                                    //Tracing only follows hooking...
                                    //String NullString = getClass().toString();
                                    //for(int i = 1; i <= 4; i++ ) {
                                    try {
                                        String StaticClassName = Thread.currentThread().getStackTrace()[4].getClassName();
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name %s Method is: %s with return of: %s and with parameters of length %s: %s", StaticClassName, param.method.getName(), paramTypesReturn, String.valueOf(paramlenths), paramTypes));
                                    } catch (Throwable ex) {
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name NULL Method is: %s with return of: %s and with parameters of length %s: %s", param.method.getName(), paramTypesReturn, String.valueOf(paramlenths), paramTypes));
                                    }
                                    //}
                                    //String classname = String.class.toString();
                                    //String className = MethodBase.GetCurrentMethod().Name;

                                } else {
                                    try {
                                        String StaticClassName = Thread.currentThread().getStackTrace()[4].getClassName();
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name %s Method is: %s and with parameters of length %s: %s", StaticClassName, param.method.getName(), String.valueOf(paramlenths), paramTypes));
                                    } catch (Throwable ex) {
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name NULL Method is: %s and with parameters of length %s: %s", param.method.getName(), String.valueOf(paramlenths), paramTypes));
                                    }
                                }
                                return;
                            } else {

                                //XposedBridge.log("Hooking in class " + param.thisObject.getClass());
                                log(String.format("Class: %s method: %s with parameters of length %s : %s", param.thisObject.getClass().getName(),
                                        param.method.getName(), String.valueOf(paramlenths), paramTypes));
                                if (param.getResult() != null) {
                                    log(String.format("Class: %s method: %s with return of: %s", param.thisObject.getClass().getName(),
                                            param.method.getName(), paramTypesReturn));
                                }
                                /////////////////////////////////////////////////////////////////////////////
                                if (prefs.getBoolean(lpparam.packageName + "/PlaceHolding", false)) {
                                    Field[] fields = param.thisObject.getClass().getDeclaredFields();
                                    for (Field f: fields) {
                                        try {
                                            f.setAccessible(true);
                                            Object o = f.get(param.thisObject.getClass());
                                            int modifier = f.getModifiers();
                                            log(String.format("Declared field name: " + f.getName() +
                                                    " Isaccessible: " +
                                                    f.isAccessible() +
                                                    " Isprivate: " +
                                                    Modifier.isPrivate(modifier) +
                                                    " Isstatic: " +
                                                    Modifier.isStatic(modifier) +
                                                    " Isfinal: " +
                                                    Modifier.isFinal(modifier) +
                                                    " Value: " +
                                                    o
                                            ));
                                        } catch (IllegalArgumentException e) {} catch (IllegalAccessException e) {}
                                    }
                                }


                                /////////////////////////////////////////////////////////////////////////////

                            }
                        }
                    };


                    if (CLASSES_TO_HOOK.isEmpty()) {
                        XposedBridge.log("Your fucking Array is empty!!!");
                        return;
                    }

                    XposedBridge.log(CLASSES_TO_HOOK.toString());


                    String sLib = (String) param.args[0];

                    Boolean triggercall = false;
                    if (ar1.contains(sLib)) {
                        sLib = "RASLINSAYSSKIPME!";
                        triggercall = false;
                    } else {
                        if (CLASSES_TO_HOOK.contains(sLib)) {
                            ar1.add(sLib);
                            triggercall = true;
                        } else {
                            triggercall = false;
                        }
                    }

                    //XposedBridge.log("Loaded Grep Loaded Class is: " + sLib);
                    if (triggercall) {
                        XposedBridge.log("Grep: " + sLib);
                        try {
                            Class <?> classToHook = XposedHelpers.findClass(sLib, lpparam.classLoader);

                            Method[] methods = classToHook.getDeclaredMethods();
                            //Field[] fields = classToHook.getDeclaredFields();
                            for (Method method: methods) {
                                try {
                                    if (Modifier.isStatic(method.getModifiers())) {
                                        XposedBridge.log("Modifier.isStatic: " + method);
                                        XposedBridge.hookMethod(method, hook);
                                    } else if (Modifier.isAbstract(method.getModifiers())) {
                                        XposedBridge.log("Modifier.isAbstract: " + method);
                                        XposedBridge.hookMethod(method, hook);
                                    } else
                                        XposedBridge.log("Looks Good Hooking Method: " + method);
                                    XposedBridge.hookMethod(method, hook);
                                } catch (NoSuchFieldError ex) {

                                } catch (Throwable ex) {

                                }
                            }
                        } catch (Throwable ex) {
                            XposedBridge.log("ERROR HOOKING ERROR REDIRECTING: " + sLib);
                        }
                    }

                }
            });
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END MethodRedirect
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN DumpMethodReturn
        // TODO DumpMethodReturn Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/DumpMethodReturn", false)) {
            final String MethodPort = prefs.getString(lpparam.packageName + "/MethodReturnMethod", "");
            final String ClassHost = prefs.getString(lpparam.packageName + "/MethodReturnClass", "");
            final String ReturnString = prefs.getString(lpparam.packageName + "/MethodReturnChange", "");

            //check for int
            boolean checkint = true;
            try {
                Integer.parseInt(ReturnString);
            } catch (NumberFormatException e) {
                checkint = false;
            } catch (NullPointerException e) {
                checkint = false;
            }
            final boolean checkint2 = checkint;

            XposedBridge.hookAllMethods(XposedHelpers.findClass(ClassHost, lpparam.classLoader), MethodPort, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("We are in " + ClassHost + MethodPort + " Method Change!!!!");
                    XposedBridge.log("We are returning " + ReturnString);


                    if (ReturnString.equals("!true")) {
                        param.setResult(true);
                        XposedBridge.log("We Change Method with bool true");
                    } else if (ReturnString.equals("!false")) {
                        param.setResult(false);
                        XposedBridge.log("We Change Method with bool false");
                    } else if (checkint2) {
                        Integer ReturnStringInt = Integer.parseInt(ReturnString);
                        param.setResult(ReturnStringInt);
                        XposedBridge.log("We Change Method with Int");
                    } else {
                        param.setResult(ReturnString);
                        XposedBridge.log("We Change Method with string");
                    }

                }
            });
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN  Libinject
        // TODO Libinject Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/LibInjections", false)) {
            XposedBridge.log("Libinject inside Game");
            XposedBridge.log("Flushing libconfig.txt");
            File root2 = new File(Environment.getExternalStorageDirectory(), "libconfig.txt");
            String nBody = "";
            FileWriter nwriter = new FileWriter(root2);
            nwriter.append(nBody);
            nwriter.flush();
            nwriter.close();
            XposedBridge.log("Injecting Native Functions");
            //File root = new File("/data/data/org.raslin777.advancedLogging/libconfig.txt");
            root2.createNewFile();
            File root = new File(Environment.getExternalStorageDirectory(), "libconfig.txt");
            /*
            if (prefs.getBoolean(lpparam.packageName + "/dvmDefineClass", false)) {
                try {
                    String sBody = "dvmDefineClass=1" + System.getProperty( "line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting dvmDefineClass");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            */
            if (prefs.getBoolean(lpparam.packageName + "/strstr", false)) {
                try {
                    String sBody = "strstr=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting strstr");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/fopen", false)) {
                try {
                    String sBody = "fopen=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting fopen");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/readdir", false)) {
                try {
                    String sBody = "readdir=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting readdir");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/unlink", false)) {
                try {
                    String sBody = "unlink=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting unlink");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/ptrace", false)) {
                try {
                    String sBody = "ptrace=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting ptrace");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/blockptrace", false)) {
                try {
                    String sBody = "blockptrace=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting blockptrace");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/open", false)) {
                try {
                    String sBody = "open=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting open");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/prctl", false)) {
                try {
                    String sBody = "prctl=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting prctl");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/mprotect", false)) {
                try {
                    String sBody = "mprotect=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting mprotect");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/mono_image_open_from_data_with_name", false)) {
                try {
                    String sBody = "mono_image_open_from_data_with_name=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting mono_image_open_from_data_with_name");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/kill", false)) {
                try {
                    String sBody = "kill=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting kill");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }

            if (prefs.getBoolean(lpparam.packageName + "/dump_mmap", false)) {
                try {
                    String sBody = "dump_mmap=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting dump_mmap");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }

            if (prefs.getBoolean(lpparam.packageName + "/strcpy", false)) {
                try {
                    String sBody = "strcpy=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting strcpy");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }
            if (prefs.getBoolean(lpparam.packageName + "/dump_mprotect", false)) {
                try {
                    String sBody = "dump_mprotect=1" + System.getProperty("line.separator");
                    FileWriter writer = new FileWriter(root, true);
                    writer.append(sBody);
                    writer.flush();
                    writer.close();
                    XposedBridge.log("Injecting dump_mprotect");
                } catch (IOException e) {
                    XposedBridge.log("Error in xposedjnihook");
                }
            }

            System.load(libPath + "libxposedjnihook.so");
            XposedBridge.log("Loaded Native Done");
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END  Libinject
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN  SwapLibFiles
        // TODO SwapLibFiles Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/TestNewCheck", false)) {
            findAndHookMethod("java.lang.Runtime", lpparam.classLoader, "loadLibrary", String.class, ClassLoader.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("Inside Loadlibray Hook");
                    String sLib = (String) param.args[0];
                    String sLib2 = "mod" + sLib;
                    XposedBridge.log("Inside Loadlibray is:" + sLib);
                    XposedBridge.log("Loadlibray is now:" + sLib2);
                    param.args[0] = sLib2;
                }
            });

        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END  SwapLibFiles
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN  OLDLibHide Inject
        // TODO OLDLibHide Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getBoolean(lpparam.packageName + "/OldLibhideInject", false)) {
            XposedBridge.log("Inside Game");
            System.load("/data/libhide.so");
            XposedBridge.log("Loaded libhide");
        }
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END  LibHide Inject
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN GrepMethodRedirect
        // TODO ZZZZZGrepMethodRedirect Working
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (prefs.getString(lpparam.packageName + "/GrepMethodRedirect", "").length() > 0) {
            final ArrayList < String > ar = new ArrayList < String > ();
            findAndHookMethod("java.lang.ClassLoader", lpparam.classLoader, "loadClass", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XC_MethodHook hook3 = new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            String paramTypesReturn = "";
                            String paramTypes = "";
                            int paramlenths2 = 0;
                            if (param.args != null) {
                                paramlenths2 = param.args.length;
                                if (param.args.length > 0) {
                                    for (Object arg: param.args) {
                                        String paramValue = null;
                                        if (arg instanceof java.lang.Boolean) {
                                            Boolean paramBool = (Boolean) arg;
                                            paramValue = String.valueOf(paramBool);
                                        } else if (arg instanceof String) {
                                            paramValue = (String) arg;
                                        } else if (arg instanceof Integer) {
                                            Integer paramInteger = (Integer) arg;
                                            paramValue = String.valueOf(paramInteger);
                                        } else if (arg instanceof Float) {
                                            Float paramFloat = (Float) arg;
                                            paramValue = String.valueOf(paramFloat);
                                        } else if (arg instanceof Long) {
                                            Long paramLong = (Long) arg;
                                            paramValue = String.valueOf(paramLong);
                                        } else if (arg instanceof String[]) {
                                            String[] paramValueSArray;
                                            paramValueSArray = (String[]) arg;
                                            log(String.format("Param of next method is String Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XSX";
                                        } else if (arg instanceof byte[]) {
                                            byte[] paramValueSArray;
                                            paramValueSArray = (byte[]) arg;
                                            log(String.format("Param of next method is byte Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XBX";
                                        } else if (arg instanceof int[]) {
                                            int[] paramValueSArray;
                                            paramValueSArray = (int[]) arg;
                                            log(String.format("Param of next method is int Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XIX";
                                        } else if (arg instanceof long[]) {
                                            long[] paramValueSArray;
                                            paramValueSArray = (long[]) arg;
                                            log(String.format("Param of next method is long Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XLX";
                                        } else if (arg instanceof float[]) {
                                            float[] paramValueSArray;
                                            paramValueSArray = (float[]) arg;
                                            log(String.format("Param of next method is float Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XFX";
                                        } else if (arg instanceof double[]) {
                                            double[] paramValueSArray;
                                            paramValueSArray = (double[]) arg;
                                            log(String.format("Param of next method is double Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XDX";
                                        } else if (arg instanceof char[]) {
                                            char[] paramValueSArray;
                                            paramValueSArray = (char[]) arg;
                                            log(String.format("Param of next method is char Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XCX";
                                        } else if (arg instanceof boolean[]) {
                                            boolean[] paramValueSArray;
                                            paramValueSArray = (boolean[]) arg;
                                            log(String.format("Param of next method is boolean Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XBX";
                                        } else if (arg instanceof byte[]) {
                                            byte[] paramValueSArray;
                                            paramValueSArray = (byte[]) arg;
                                            log(String.format("Param of next method is byte Array: %s", (Arrays.toString(paramValueSArray))));
                                            paramValue = "XbX";
                                        } else if (arg == null) {
                                            paramValue = "NULL";
                                        } else {
                                            Object tmpObject = null;
                                            String redisString = "";
                                            String serializedObject = "";
                                            String Base64Object = "";
                                            try {

                                                tmpObject = arg;
                                                if (tmpObject == null) {
                                                    paramValue = "NULL";
                                                }

                                                /*
                                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                                ObjectOutputStream oos = new ObjectOutputStream( baos );
                                                oos.writeObject(tmpObject);
                                                oos.close();
                                                Base64Object = Base64.encode(baos.toByteArray(),Base64.DEFAULT).toString();
                                                log(String.format("Param of next method is Object Array[Base64]: %s", Base64Object));
                                                */

                                                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                                                ObjectOutputStream so = new ObjectOutputStream(bo);
                                                so.writeObject(tmpObject);
                                                so.flush();
                                                serializedObject = bo.toString();
                                                //paramValueObject = tmpObject.toString();
                                                log(String.format("Param of next method is Object Array: %s", arg.toString()));
                                                log(String.format("Object Array DUMP: %s", serializedObject));
                                                paramValue = "XOX";
                                            } catch (Throwable ex) {
                                                paramValue = arg.toString();
                                            }
                                        }


                                        if (paramValue != null)
                                            paramTypes += " " + paramValue + " |=|";

                                    }
                                }
                            }

                            if (param.getResult() != null) {

                                String str1 = param.getResult().toString();
                                String str2 = "[B@";
                                String str3 = "[Ljava.lang.String;@";
                                String paramValueReturn = null;

                                if (param.getResult() instanceof java.lang.Boolean) {
                                    Boolean paramBool = (Boolean) param.getResult();
                                    paramValueReturn = String.valueOf(paramBool);
                                }
                                if (param.getResult() instanceof String) {
                                    paramValueReturn = (String) param.getResult();
                                }
                                if (str1.toLowerCase().contains(str3.toLowerCase())) {
                                    String[] paramValueSArray;
                                    paramValueSArray = (String[]) param.getResult();
                                    log(String.format("Return of next method is Array: %s", (Arrays.toString(paramValueSArray))));
                                }
                                if (paramValueReturn != null)
                                    paramTypesReturn += paramValueReturn + ";";
                                else {
                                    try {
                                        paramTypesReturn += param.getResult().toString();
                                    } catch (Throwable ex) {
                                        paramTypesReturn += "CannotCastToString;";
                                    }
                                }
                                // Needs cleanup
                                if (str1.toLowerCase().contains(str2.toLowerCase())) {
                                    char[] hexArray = "0123456789ABCDEF".toCharArray();
                                    byte[] bytes = (byte[]) param.getResult();
                                    char[] hexChars = new char[bytes.length * 2];

                                    for (int j = 0; j < bytes.length; j++) {
                                        int v = bytes[j] & 0xFF;
                                        hexChars[j * 2] = hexArray[v >>> 4];
                                        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
                                    }
                                    String Decryted = new String(hexChars);
                                    paramTypesReturn = "Decrypted with return of: " + Decryted;
                                    log(String.format("Decrypted with return of: %s", Decryted));
                                    if (prefs.getBoolean(lpparam.packageName + "/DecodeHex", false)) {

                                        String hex = Decryted;
                                        String ascii = "";
                                        for (int i = 0; i < hex.length() - 1; i += 2) {

                                            //split the hex into pairs
                                            String pair = hex.substring(i, (i + 2));
                                            //convert hex to decimal
                                            int dec = Integer.parseInt(pair, 16);
                                            //convert the decimal to character
                                            String str;
                                            str = Character.toString((char) dec);

                                            if (dec < 32 || dec > 126 && dec < 161)
                                                str = "|";

                                            ascii = ascii + " " + str;
                                        }

                                        log(String.format("Decrypted with ascii return of: %s", ascii));
                                    }
                                }

                            } else {
                                paramTypesReturn += "NULL;";
                            }

                            if (param.thisObject == null) {
                                if (param.getResult() != null) {
                                    //Tracing only follows hooking...
                                    //String NullString = getClass().toString();
                                    //for(int i = 1; i <= 4; i++ ) {
                                    try {
                                        String StaticClassName = Thread.currentThread().getStackTrace()[4].getClassName();
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name %s Method is: %s with return of: %s and with parameters of length %s: %s", StaticClassName, param.method.getName(), paramTypesReturn, String.valueOf(paramlenths2), paramTypes));
                                    } catch (Throwable ex) {
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name NULL Method is: %s with return of: %s and with parameters of length %s: %s", param.method.getName(), paramTypesReturn, String.valueOf(paramlenths2), paramTypes));
                                    }
                                    //}
                                    //String classname = String.class.toString();
                                    //String className = MethodBase.GetCurrentMethod().Name;

                                } else {
                                    try {
                                        String StaticClassName = Thread.currentThread().getStackTrace()[4].getClassName();
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name %s Method is: %s and with parameters of length %s: %s", StaticClassName, param.method.getName(), String.valueOf(paramlenths2), paramTypes));
                                    } catch (Throwable ex) {
                                        log(String.format("Class:CLASS IS STATIC!!!Class Name NULL Method is: %s and with parameters of length %s: %s", param.method.getName(), String.valueOf(paramlenths2), paramTypes));
                                    }
                                }
                                return;
                            } else {

                                //XposedBridge.log("Hooking in class " + param.thisObject.getClass());
                                log(String.format("Class: %s method: %s with parameters of length %s : %s", param.thisObject.getClass().getName(),
                                        param.method.getName(), String.valueOf(paramlenths2), paramTypes));
                                if (param.getResult() != null) {
                                    log(String.format("Class: %s method: %s with return of: %s", param.thisObject.getClass().getName(),
                                            param.method.getName(), paramTypesReturn));
                                }
                            }
                        }
                    };
                    String sLib = (String) param.args[0];
                    if (ar.contains(sLib)) {
                        sLib = "RASLINSAYSSKIPME!";
                    } else {
                        ar.add(sLib);
                    }
                    String grepnames = (prefs.getString(lpparam.packageName + "/GrepMethodRedirect", ""));
                    //XposedBridge.log("Loaded Grep Loaded Class is: " + sLib);
                    if (sLib.contains(grepnames)) {
                        XposedBridge.log("Grep: " + sLib);
                        try {
                            Class <?> classToHook = XposedHelpers.findClass(sLib, lpparam.classLoader);

                            Method[] methods2 = classToHook.getDeclaredMethods();
                            //Field[] fields = classToHook.getDeclaredFields();
                            for (Method method2: methods2) {
                                try {
                                    if (Modifier.isStatic(method2.getModifiers())) {
                                        XposedBridge.log("Modifier.isStatic: " + method2);
                                        XposedBridge.hookMethod(method2, hook3);
                                    } else if (Modifier.isAbstract(method2.getModifiers())) {
                                        XposedBridge.log("Modifier.isAbstract: " + method2);
                                        XposedBridge.hookMethod(method2, hook3);
                                    } else
                                        XposedBridge.log("Looks Good Hooking Method: " + method2);
                                    XposedBridge.hookMethod(method2, hook3);
                                } catch (NoSuchFieldError ex) {

                                } catch (Throwable ex) {

                                }
                            }
                        } catch (Throwable ex) {
                            XposedBridge.log("ERROR HOOKING ERROR REDIRECTING AGAIN: " + sLib);

                        }
                    }
                }

            });
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //END  GrepMethodRedirect
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //BEGIN  WaitForDebug60Sec
        // TODO WaitForDebug60Sec Testing
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        if (prefs.getBoolean(lpparam.packageName + "/WaitForDebug",false)) {
            if (oneshot == 0) {
                String cmdlinestring1 = "rename /data/data/" + lpparam.packageName +
                        "/lib/libunity.so /data/data/" + lpparam.packageName + "/lib/librealunity.so";

                String cmdlinestring2 = "cp" + libPath + "libxposedjnihook.so /data/data/" +
                        lpparam.packageName + "/lib/libunity.so";

                XposedBridge.log(cmdlinestring1);
                XposedBridge.log(cmdlinestring2);
                XposedBridge.log("Running Command1!!");
                Shell.SU.run(cmdlinestring1);
                XposedBridge.log("Running Command2!!");
                Shell.SU.run(cmdlinestring2);
                XposedBridge.log("Command ran!!!");
                oneshot++;
            }
        }

        /*
        if (prefs.getBoolean(lpparam.packageName + "/WaitForDebug",true)) {
//librealunity
            String cmdlinestring1 = "find /data/data/"+lpparam.packageName+"/lib/ -name \"libunity.so\" -size -160k -exec rm {} \\;";
            String cmdlinestring2 = "rename /data/data/"+lpparam.packageName+"/lib/librealunity.so /data/data/"+lpparam.packageName+"/lib/libunity.so";
            XposedBridge.log(cmdlinestring1);
            XposedBridge.log(cmdlinestring2);
            XposedBridge.log("Running Command1!!");
            Shell.SU.run(cmdlinestring1);
            XposedBridge.log("Running Command2!!");
            Shell.SU.run(cmdlinestring2);
            XposedBridge.log("Command ran!!!");
        }

/data/data/org.raslin777.advancedLogging/lib

rename /data/app/com.nianticlabs.pokemongo-1/lib/arm/libunity.so /data/app/com.nianticlabs.pokemongo-1/lib/arm/librealunity.so

cp /data/data/org.raslin777.advancedLogging/lib/libxposedjnihook.so /data/app/com.nianticlabs.pokemongo-1/lib/arm/libunity.so

chmod 755 /data/app/com.nianticlabs.pokemongo-1/lib/arm/libunity.so

==========================================================================================================================================================================================================================================================================

find /data/app/com.nianticlabs.pokemongo-1/lib/arm/ -name "libunity.so" -size -160k -exec rm {} \;

rename /data/app/com.nianticlabs.pokemongo/lib/arm/librealunity.so /data/app/com.nianticlabs.pokemongo-1/lib/arm/libunity.so





        */
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    }


    public enum Mode {
        SUPPRESS,
        DEFAULT,
        OVERRIDE
    }



}