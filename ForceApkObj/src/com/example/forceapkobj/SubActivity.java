package com.example.forceapkobj;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Toast;

public class SubActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		handleException();
	}

	public void handleException() {
		Toast.makeText(this, "≥…π¶”≥…‰", Toast.LENGTH_LONG).show();
	}

}
