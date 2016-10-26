package org.raslin777.advancedLogging;

import java.util.ArrayList;
import java.util.List;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

class AppListAdapter extends BaseAdapter {
	
	interface DataProvider {
		List<AppInfo> getAppList();
	}

	private Context context;

	private boolean enabledOnly = false;
	private DataProvider dataProvider;
	private List<AppInfo> filteredApps = new ArrayList<AppInfo>(100);
	private StringBuilder summaryBuilder = new StringBuilder();
	
	AppListAdapter(Context context, DataProvider dataProvider, boolean enabledOnly) {
		this.context = context;
		this.dataProvider = dataProvider; 
		this.enabledOnly = enabledOnly;
	}
	
	@SuppressLint("DefaultLocale")
	void filter(String filter) {
		if (enabledOnly) {
			filteredApps.clear();
			for (AppInfo app : dataProvider.getAppList()) {
				if (app.isEnabled()) {
					filteredApps.add(app);
				}
			}
		} else {
			filteredApps.clear();
			filter = filter == null ? null : filter.trim().toLowerCase();
			for (AppInfo app : dataProvider.getAppList()) {
				if (filter == null || filter.length() == 0 ||
					app.name.toLowerCase().contains(filter) ||
					app.packageName.toLowerCase().contains(filter)) {
					filteredApps.add(app);
				}
			}
		}
		this.notifyDataSetChanged();
	}
	
	public void refreshData() {
		filter(null);
	}
	
	@Override
	public int getCount() {
		return filteredApps.size();
	}

	@Override
	public Object getItem(int position) {
		return filteredApps.get(position);
	}

	@Override
	public long getItemId(int position) {
		return position;
	}
	
	@Override
	public View getView(int position, View convertView, ViewGroup parent) {	
		RowStateHolder stateHolder;
		View view;
		if (convertView == null) {
			stateHolder = new RowStateHolder(context, parent);
			view = stateHolder.getRootView();
		} else {
			view = convertView;
			stateHolder = (RowStateHolder)view.getTag();
		}

		AppInfo app = filteredApps.get(position);
		stateHolder.setAppName(app.name);
		stateHolder.setPackageName(app.packageName);
		summaryBuilder.setLength(0);
		/*
		summaryBuilder.append(app.MethodReturnClass == null || app.MethodReturnClass.trim().length() == 0 ? "No proxy" : "Proxy: " + app.MethodReturnClass + ":" + app.MethodReturnMethod);
		if (app.LogAllClasses) {
			summaryBuilder.append(", LogClasses");
		}
		if (app.PackagePathRedirect) {
			summaryBuilder.append(", PkgPathReDIR");
		}
		if (app.MethodRedirect) {
			summaryBuilder.append(", MethReDIR");
		}
		if (app.CreateGcore != null) {
			summaryBuilder.append(", SleepLib");
		}
		if (app.DumpDexFile) {
			summaryBuilder.append(", ExtraLog");
		}
		if (app.TestNewCheck) {
			summaryBuilder.append(", TestNewCheck");
		}
		if (app.LibInjections) {
			summaryBuilder.append(", LibInjections");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", dvmDefineClass");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", strstr");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", fopen");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", readdir");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", unlink");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", ptrace");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", open");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", prctl");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", mprotect");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", mono_image_open_from_data_with_name");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", kill");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", strcpy");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", dump_mmap");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", dump_mprotect");
		}
		if (app.dvmDefineClass) {
			summaryBuilder.append(", blockptrace");
		}
*/
		stateHolder.setSummary(summaryBuilder.toString());
        stateHolder.setIcon(app.icon);
		stateHolder.setColor(app.isEnabled() ? Color.WHITE : Color.GRAY);
		return view;
	}
	
    public class RowStateHolder {
    	private View view;
    	
    	private TextView appNameText;
    	private TextView packageText;
    	private TextView summaryText;
		private ImageView appIcon;
    	
		public RowStateHolder(final Context context, ViewGroup parentView) {
			LayoutInflater mInflater = (LayoutInflater)context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
			view = mInflater.inflate(R.layout.app_list_item, parentView, false);
			view.setTag(this);
			
			appNameText = (TextView)view.findViewById(R.id.appNameText);
			packageText = (TextView)view.findViewById(R.id.packageText);
			summaryText = (TextView)view.findViewById(R.id.summaryText);
			appIcon = (ImageView)view.findViewById(R.id.appIcon);
		}
		
		public void setColor(int color) {
			appNameText.setTextColor(color);
			packageText.setTextColor(color);
			summaryText.setTextColor(color);
		}

		public void setAppName(String name) {
			appNameText.setText(name);
		}

		public void setPackageName(String packageName) {
			packageText.setText(packageName);
		}

		public void setSummary(String summary) {
			summaryText.setText(summary);
		}

        public void setIcon(Drawable icon) {
            appIcon.setImageDrawable(icon);
        }

		public View getRootView() {
			return view;
		}
    }
}