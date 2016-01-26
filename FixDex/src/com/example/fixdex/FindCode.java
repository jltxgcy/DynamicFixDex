package com.example.fixdex;

public class FindCode {
	
	static {
		System.loadLibrary("findcode");
	}
	
	public static native int findCode(String className, String methodName);

}
