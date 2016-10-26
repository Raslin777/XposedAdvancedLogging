package org.raslin777.advancedLogging;

import android.graphics.drawable.Drawable;

class AppInfo implements Comparable<AppInfo> {
	public final String name;
	public final String packageName;
	public final Drawable icon;
	
	String MethodReturnClass = null;
	String MethodReturnMethod = null;
    String MethodReturnChange = null;

	boolean CreateGcore = false;
	String GrepMethodRedirect = null;
	boolean WaitForDebug = false;
	boolean DumpDexFile = false;
	//public boolean SqlCipher = false;
	boolean BypassSSL = false;
	boolean TestNewCheck = false;
	boolean LibInjections = false;
	boolean strstr = false;
	boolean fopen = false;
	boolean readdir = false;
	boolean unlink = false;
	boolean ptrace = false;
	boolean blockptrace = false;
	public boolean open = false;
	boolean prctl = false;
	boolean mprotect = false;
	boolean mono_image_open_from_data_with_name = false;
	boolean kill = false;
	boolean strcpy = false;

	boolean dump_mmap = false;
	boolean dump_mprotect = false;
	/*
	public boolean dvmDefineClass = false;
	*/
	boolean OldLibhideInject = false;

	boolean PackagePathRedirect = false;
	boolean MethodRedirect = false;
	
	boolean LogAllClasses = false;
    String GrepClass = null;

    boolean PlaceHolding = false;
    boolean DecodeHex = false;

	AppInfo(String name, String packageName, Drawable icon) {
		this.name = name;
		this.packageName = packageName;
		this.icon = icon;
	}
	
	boolean isEnabled() {
		return (MethodReturnClass != null) || CreateGcore || GrepMethodRedirect != null || WaitForDebug || OldLibhideInject || DumpDexFile ||  BypassSSL || TestNewCheck || LibInjections || LogAllClasses || PackagePathRedirect || MethodRedirect;
	}

	@Override
	public int compareTo(AppInfo o) {
		return name.compareToIgnoreCase(o.name);
	}
}
