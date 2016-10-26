# XposedAdvancedLogging

http://forum.xda-developers.com/xposed/modules/mod-advanced-logging-t3472533

Advanced Logging is a Xposed to provide more transparency to applications.

Filter Logcat for AdvancedLogging

Features:
1) Bypass SSL Pinning.
2) Dump GCore(This will try to dump a gcore(x32 only for now) to the external sdcard after 5secs of app launch, dump take about ~15mins or longer ,core will be located in /Android/data/org.raslin777.advancedLogging) 
3) Dump Dex will try to dump the dex of application to its data folder locations.
4) Unity Hook(Allows you to modify the dex file but redirect the unity loading to another apk ie. modded apk installed but hooked pointed to unmodded version, help when application is checking for sigs or changes in the dex)
5) GrepHookAllMethods(Type a name and if the loaded class contains that name we will hook all methods of that class, This will display in logcat all method calls with their parameters and values with their return values as they are called.)
6) Log All Classes(this will log to a myfile.txt to the data folder of the hooked application all the classes called)
7) Grep LogAllClasses(Filters the output of #6)
8) Hook all methods of classes(This will look in /data/data/org.raslin777.advancedLogging/classes.txt for classes to hook, it will hook all methods of that class, This will display in logcat all method calls with their parameters and values with their return values as they are called)
9) Hook Fields, Will also output classes fields with the logcat.
10) DecodeHex will change Hex to Ascii code
11) Change Return (Type Class and method, and type the return you want. This does not change parameters)
12) Library Injection(This will hook into libc.so select with function you want to send to logcat. Still working on more output for this. write to external sdcard need for this, dont mind the mono hook for dumping unity)

Native/System Function(REQUIRES REBOOT)
1)App Perm[Working on 6.0.1](Application to inject permissions into, will not display in properties but should work check xposed log for success or failure)
1)Perm to add[Working on 6.0.1](Type the permission to add if none typed will add write to external sdcard) 
2) Debug all Apps(Enable Debug all apps and allows apps to be selected for debugging via settings debugging(So we can wait for debugger))
