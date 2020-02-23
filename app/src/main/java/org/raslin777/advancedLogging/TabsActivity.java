package org.raslin777.advancedLogging;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import android.annotation.SuppressLint;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;

import com.flurry.android.FlurryAgent;


public class TabsActivity extends FragmentActivity implements AppListAdapter.DataProvider {

	private static final String TAG = TabsActivity.class.getSimpleName();

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments for each of the sections. We use a
	 * {@link android.support.v4.app.FragmentPagerAdapter} derivative, which
	 * will keep every loaded fragment in memory. If this becomes too memory
	 * intensive, it may be best to switch to a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter}.
	 */
	SectionsPagerAdapter mSectionsPagerAdapter;

	private List<AppInfo> apps;

	/**
	 * The {@link ViewPager} that will host the section contents.
	 */
	ViewPager mViewPager;
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		//getMenuInflater().inflate(R.menu.tabs, menu);
		Button button = (Button) findViewById(R.id.nativebutton);

		button.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View view) {
				//Toast.makeText(TabsActivity.this, "Button Clicked",	Toast.LENGTH_SHORT).show();
				Intent i = new Intent(getApplicationContext(), SettingsActivityNative.class);
				startActivity(i);
			}

		});
		return true;
	}
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_tabs);

		FlurryAgent.setLogEnabled(false);
		FlurryAgent.init(this, "46KZTMZJX5D7HH3CWBWX");
		// Create the adapter that will return a fragment for each of the three
		// primary sections of the app.
		mSectionsPagerAdapter = new SectionsPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager with the sections adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mSectionsPagerAdapter);

		reloadAppListAsync();
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
	}

	void updatePackage(String packageName) {
		AppInfo _target = null;
		for (int i = apps.size() - 1; i >= 0; i--) {
			AppInfo app = (AppInfo)apps.get(i);
			if (app.packageName.equals(packageName)) {
				_target = app;
				break;
			}
		}

		if (_target != null) {
			final AppInfo target = _target;

			loadAppSettings(target);
			for (Fragment f : mSectionsPagerAdapter.fragments)
				if (f instanceof AppsListFragment) {
				((AppsListFragment)f).appsChanged();
			}
		}
	}

	void reloadAppListAsync() {
		AsyncTask<Integer, Void, List<AppInfo>> task = new AsyncTask<Integer, Void, List<AppInfo>>() {

			private ProgressDialog dialog;

			@Override
			protected List<AppInfo> doInBackground(Integer... args) {
				try {
					ArrayList<AppInfo> apps = new ArrayList<AppInfo>();
		            PackageManager pm = getPackageManager();
		            List<PackageInfo> appListInfo = pm.getInstalledPackages(0);
		            for (PackageInfo p : appListInfo) {
		            	String name = p.applicationInfo.packageName;
						Drawable icon = p.applicationInfo.loadIcon(pm);
		            	try {
		            		name = p.applicationInfo.loadLabel(pm).toString();
		            	} catch (Exception ex) {
		            	}
		            	AppInfo app = new AppInfo(name, p.applicationInfo.packageName, icon);
		    			apps.add(app);
		    			loadAppSettings(app);
		            }
		            Collections.sort(apps);
		            return apps;
		        } catch (Exception e) {
		        	Log.e(TAG, "Error while load packages!", e);
		        	return null;
		        }
		        finally {
		        }
		    }

			@Override
			protected void onPreExecute() {
				dialog = ProgressDialog.show(TabsActivity.this, "", "Loading. Please wait...", true);
				dialog.setIndeterminate(true);
				dialog.show();
			}

			@Override
			protected void onPostExecute(List<AppInfo> result) {
				dialog.dismiss();
				apps = result;
				for (Fragment f : mSectionsPagerAdapter.fragments)
					if (f instanceof AppsListFragment) {
					((AppsListFragment)f).appsChanged();
				}
			}
		};
		task.execute();
	}

	@SuppressLint("WorldReadableFiles")
	private void loadAppSettings(AppInfo app) {
		
		SharedPreferences prefs = getApplicationContext().getSharedPreferences("ModSettings", Context.MODE_PRIVATE);
		if (prefs.getBoolean(app.packageName + "/" + "DumpMethodReturn", false)) {
			app.MethodReturnClass = prefs.getString(app.packageName + "/" + "MethodReturnClass", "");
			app.MethodReturnMethod = prefs.getString(app.packageName + "/" + "MethodReturnMethod", "");
			app.MethodReturnChange = prefs.getString(app.packageName + "/" + "MethodReturnChange", "");
		} else {
			app.MethodReturnClass = null;
			app.MethodReturnMethod = null;
			app.MethodReturnChange = null;
		}
		app.CreateGcore = prefs.getBoolean(app.packageName + "/" + "CreateGcore", false);

		app.GrepMethodRedirect = prefs.getString(app.packageName + "/GrepMethodRedirect", "");
		if (app.GrepMethodRedirect.length() == 0)
			app.GrepMethodRedirect = null;

		app.WaitForDebug = prefs.getBoolean(app.packageName + "/" + "WaitForDebug", false);

		app.DumpDexFile = prefs.getBoolean(app.packageName + "/" + "DumpDexFile", false);
		app.BypassSSL = prefs.getBoolean(app.packageName + "/" + "BypassSSL", false);
		//app.SqlCipher = prefs.getBoolean(app.packageName + "/" + "SqlCipher", false);
		app.TestNewCheck = prefs.getBoolean(app.packageName + "/" + "TestNewCheck", false);
		app.LibInjections = prefs.getBoolean(app.packageName + "/" + "LibInjections", false);

		app.strstr = prefs.getBoolean(app.packageName + "/" + "strstr", false);
		app.fopen = prefs.getBoolean(app.packageName + "/" + "fopen", false);
		app.readdir = prefs.getBoolean(app.packageName + "/" + "readdir", false);
		app.unlink = prefs.getBoolean(app.packageName + "/" + "unlink", false);
		app.ptrace = prefs.getBoolean(app.packageName + "/" + "ptrace", false);
		app.blockptrace = prefs.getBoolean(app.packageName + "/" + "blockptrace", false);
		app.open = prefs.getBoolean(app.packageName + "/" + "open", false);
		app.prctl = prefs.getBoolean(app.packageName + "/" + "prctl", false);
		app.mprotect = prefs.getBoolean(app.packageName + "/" + "mprotect", false);
		app.mono_image_open_from_data_with_name = prefs.getBoolean(app.packageName + "/" + "mono_image_open_from_data_with_name", false);
		app.kill = prefs.getBoolean(app.packageName + "/" + "kill", false);
		app.strcpy = prefs.getBoolean(app.packageName + "/" + "strcpy", false);
		app.dump_mmap = prefs.getBoolean(app.packageName + "/" + "dump_mmap", false);
		app.dump_mprotect = prefs.getBoolean(app.packageName + "/" + "dump_mprotect", false);
        //app.dvmDefineClass = prefs.getBoolean(app.packageName + "/" + "dvmDefineClass", false);
		app.OldLibhideInject = prefs.getBoolean(app.packageName + "/" + "OldLibhideInject", false);

		app.PackagePathRedirect = prefs.getBoolean(app.packageName + "/" + "PackagePathRedirect", false);
		app.MethodRedirect = prefs.getBoolean(app.packageName + "/" + "MethodRedirect", false);
		app.LogAllClasses = prefs.getBoolean(app.packageName + "/" + "LogAllClasses", false);
        app.GrepClass = prefs.getString(app.packageName + "/GrepClass", "");
        if (app.GrepClass.length() == 0)
            app.GrepClass = null;
        app.PlaceHolding =  prefs.getBoolean(app.packageName + "/" + "PlaceHolding", false);
        app.DecodeHex =  prefs.getBoolean(app.packageName + "/" + "DecodeHex", false);
	}

	@SuppressLint("WorldReadableFiles")
	void saveAppSettings(Map<String,Object> app) {
		SharedPreferences prefs = getApplicationContext().getSharedPreferences("ModSettings", Context.MODE_PRIVATE);
		Editor e = prefs.edit();
		String packageName = (String)app.get("packageName");
		e.putBoolean(packageName + "/" + "DumpMethodReturn", app.get("MethodReturnClass") != null);
		e.putString(packageName + "/" + "MethodReturnClass", (String) app.get("MethodReturnClass"));
        e.putString(packageName + "/" + "MethodReturnMethod", (String)app.get("MethodReturnMethod"));
        e.putString(packageName + "/" + "MethodReturnChange", (String)app.get("MethodReturnChange"));

		e.putBoolean(packageName + "/" + "CreateGcore", (Boolean)app.get("CreateGcore"));
		e.putString(packageName + "/" + "GrepMethodRedirect", (String)app.get("GrepMethodRedirect"));
		e.putBoolean(packageName + "/" + "WaitForDebug", (Boolean) app.get("WaitForDebug"));
		e.putBoolean(packageName + "/" + "DumpDexFile", (Boolean) app.get("DumpDexFile"));
		e.putBoolean(packageName + "/" + "TestNewCheck", (Boolean)app.get("TestNewCheck"));
		e.putBoolean(packageName + "/" + "BypassSSL", (Boolean)app.get("BypassSSL"));

		e.putBoolean(packageName + "/" + "LibInjections", (Boolean)app.get("LibInjections"));
		e.putBoolean(packageName + "/" + "strstr", (Boolean)app.get("strstr"));
		e.putBoolean(packageName + "/" + "fopen", (Boolean)app.get("fopen"));
		e.putBoolean(packageName + "/" + "readdir", (Boolean)app.get("readdir"));
		e.putBoolean(packageName + "/" + "unlink", (Boolean)app.get("unlink"));
		e.putBoolean(packageName + "/" + "ptrace", (Boolean)app.get("ptrace"));
		e.putBoolean(packageName + "/" + "blockptrace", (Boolean)app.get("blockptrace"));
		e.putBoolean(packageName + "/" + "open", (Boolean)app.get("open"));
		e.putBoolean(packageName + "/" + "prctl", (Boolean)app.get("prctl"));
		e.putBoolean(packageName + "/" + "mprotect", (Boolean)app.get("mprotect"));
		e.putBoolean(packageName + "/" + "mono_image_open_from_data_with_name", (Boolean)app.get("mono_image_open_from_data_with_name"));
		e.putBoolean(packageName + "/" + "kill", (Boolean)app.get("kill"));
		e.putBoolean(packageName + "/" + "strcpy", (Boolean)app.get("strcpy"));
		e.putBoolean(packageName + "/" + "dump_mmap", (Boolean)app.get("dump_mmap"));
		e.putBoolean(packageName + "/" + "dump_mprotect", (Boolean)app.get("dump_mprotect"));
//		e.putBoolean(packageName + "/" + "dvmDefineClass", (Boolean)app.get("dvmDefineClass"));
		e.putBoolean(packageName + "/" + "PackagePathRedirect", (Boolean)app.get("PackagePathRedirect"));
		e.putBoolean(packageName + "/" + "OldLibhideInject", (Boolean)app.get("OldLibhideInject"));

		e.putBoolean(packageName + "/" + "LogAllClasses", (Boolean)app.get("LogAllClasses"));
        e.putString(packageName + "/" + "GrepClass", (String)app.get("GrepClass"));

        e.putBoolean(packageName + "/" + "MethodRedirect", (Boolean)app.get("MethodRedirect"));
        e.putBoolean(packageName + "/" + "PlaceHolding", (Boolean)app.get("PlaceHolding"));
        e.putBoolean(packageName + "/" + "DecodeHex", (Boolean)app.get("DecodeHex"));

		e.commit();
	}

	@Override
	public List<AppInfo> getAppList() {
		return apps;
	}


	/**
	 * A {@link FragmentPagerAdapter} that returns a fragment corresponding to
	 * one of the sections/tabs/pages.
	 */
	public class SectionsPagerAdapter extends FragmentPagerAdapter {

		Fragment[] fragments = {
				new AllAppsSectionFragment(),
				new EnabledAppsSectionFragment(),
				//new BackupFragment()
		};

		public SectionsPagerAdapter(FragmentManager fm) {
			super(fm);
		}

		@Override
		public Fragment getItem(int position) {
			return fragments[position];
		}

		@Override
		public int getCount() {
			return fragments.length;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case 0:
				return "All Apps";
			case 1:
				return "Enabled Apps";
			case 2:
				return "Backup/Restore";
			}
			return null;
		}
	}


}
