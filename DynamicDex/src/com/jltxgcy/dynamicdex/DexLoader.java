package com.jltxgcy.dynamicdex;

public class DexLoader {
	static {
		System.loadLibrary("dexloader");
	}

	public static native void load(String path);

	public static native void run();
}
