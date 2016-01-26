package com.jltxgcy.dynamicdex;

import android.app.Application;
import android.content.Context;

public class StubApplication extends Application {
	
	@Override
	protected void attachBaseContext(Context base) {
		super.attachBaseContext(base);
		DexLoader.load("com.jltxgcy.dynamicdex");
	}

	@Override
	public void onCreate() {
		DexLoader.run();
	}
}
