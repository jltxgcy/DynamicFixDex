package com.example.fixdex;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import dalvik.system.DexClassLoader;

public class MainActivity extends Activity {
	private Button button;
	/*private byte[] exceptionCode= {0x02,0x00,0x01,0x00,0x01,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
			0x22,0x00,0x1C,0x00,0x70,0x10,0x1D,0x00,0x00,0x00,0x27,0x00};*/
	private byte[] exceptionCode= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00};

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		DexClassLoader dexClassLoader = new DexClassLoader("/sdcard/payload/ForceApkObj.apk", "/sdcard/payload/", null, getClassLoader());
		button = (Button) findViewById(R.id.button1);
		button.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View arg0) {
				int codeoff = FindCode.findCode("Lcom/example/forceapkobj/SubActivity;", "handleException");
				Log.d("jltxgcy", "codeoff:" + codeoff);
				try {
					File file = new File("/sdcard/payload/classes.dex");
					byte[] dexByte = readFileBytes(file);
					String strso = "/sdcard/payload/data.so";
					writeFile(strso, dexByte, codeoff - 16, exceptionCode.length + 16);
					System.arraycopy(exceptionCode, 0, dexByte, codeoff, exceptionCode.length);
					//修改DEX file size文件头
					fixFileSizeHeader(dexByte);
					//修改DEX SHA1 文件头
					fixSHA1Header(dexByte);
					//修改DEX CheckSum文件头
					fixCheckSumHeader(dexByte);
					String str = "/sdcard/payload/classes_fix.dex";
					writeFile(str, dexByte, 0, dexByte.length);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
	}
	
	private void writeFile(String fileName, byte[] dexByte, int begin, int count) throws Exception{
		File fixFile = new File(fileName);
		if (!fixFile.exists()) {
			fixFile.createNewFile();
		}
		FileOutputStream localFileOutputStream = new FileOutputStream(fileName);
		localFileOutputStream.write(dexByte, begin, count);
		localFileOutputStream.flush();
		localFileOutputStream.close();
	}
	
	/**
	 * 修改dex头，CheckSum 校验码
	 * @param dexBytes
	 */
	private static void fixCheckSumHeader(byte[] dexBytes) {
		Adler32 adler = new Adler32();
		adler.update(dexBytes, 12, dexBytes.length - 12);//从12到文件末尾计算校验码
		long value = adler.getValue();
		int va = (int) value;
		byte[] newcs = intToByte(va);
		//高位在前，低位在前掉个个
		byte[] recs = new byte[4];
		for (int i = 0; i < 4; i++) {
			recs[i] = newcs[newcs.length - 1 - i];
			System.out.println(Integer.toHexString(newcs[i]));
		}
		System.arraycopy(recs, 0, dexBytes, 8, 4);//效验码赋值（8-11）
		System.out.println(Long.toHexString(value));
		System.out.println();
	}


	/**
	 * int 转byte[]
	 * @param number
	 * @return
	 */
	public static byte[] intToByte(int number) {
		byte[] b = new byte[4];
		for (int i = 3; i >= 0; i--) {
			b[i] = (byte) (number % 256);
			number >>= 8;
		}
		return b;
	}

	/**
	 * 修改dex头 sha1值
	 * @param dexBytes
	 * @throws NoSuchAlgorithmException
	 */
	private static void fixSHA1Header(byte[] dexBytes)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(dexBytes, 32, dexBytes.length - 32);//从32为到结束计算sha--1
		byte[] newdt = md.digest();
		System.arraycopy(newdt, 0, dexBytes, 12, 20);//修改sha-1值（12-31）
		//输出sha-1值，可有可无
		String hexstr = "";
		for (int i = 0; i < newdt.length; i++) {
			hexstr += Integer.toString((newdt[i] & 0xff) + 0x100, 16)
					.substring(1);
		}
		System.out.println(hexstr);
	}

	/**
	 * 修改dex头 file_size值
	 * @param dexBytes
	 */
	private static void fixFileSizeHeader(byte[] dexBytes) {
		//新文件长度
		byte[] newfs = intToByte(dexBytes.length);
		System.out.println(Integer.toHexString(dexBytes.length));
		byte[] refs = new byte[4];
		//高位在前，低位在前掉个个
		for (int i = 0; i < 4; i++) {
			refs[i] = newfs[newfs.length - 1 - i];
			System.out.println(Integer.toHexString(newfs[i]));
		}
		System.arraycopy(refs, 0, dexBytes, 32, 4);//修改（32-35）
	}


	/**
	 * 以二进制读出文件内容
	 * @param file
	 * @return
	 * @throws IOException
	 */
	private static byte[] readFileBytes(File file) throws IOException {
		byte[] arrayOfByte = new byte[1024];
		ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
		FileInputStream fis = new FileInputStream(file);
		while (true) {
			int i = fis.read(arrayOfByte);
			if (i != -1) {
				localByteArrayOutputStream.write(arrayOfByte, 0, i);
			} else {
				return localByteArrayOutputStream.toByteArray();
			}
		}
	}
}
