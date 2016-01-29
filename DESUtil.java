import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;

/**
 * DES加解密工具 
 * DES-64位 With SunJCE 
 * EncryptMode ECB 
 * PaddingMode PKCS5Padding With \0
 * IV 此类算法不需要向量 
 * 对应的PHP互操作代码参考同文件夹下的DesSecurityUtil.php
 */
public class DESUtil {
	private static final String CIPHER_TYPE = "DES";
	
	private static final String DEFAULT_Key = "national";

	private Cipher encryptCipher = null;

	private Cipher decryptCipher = null;

	/**
	 * 默认构造方法，使用默认密钥
	 * 
	 * @throws Exception
	 */
	public DESUtil() throws Exception {
		this(DEFAULT_Key);
	}

	/**
	 * 指定密钥构造方法
	 * 
	 * @param strKey
	 *            指定的密钥
	 * @throws Exception
	 */
	public DESUtil(String strKey) throws Exception {
		Security.addProvider(new com.sun.crypto.provider.SunJCE());
		Key key = generateKey(strKey.getBytes());

		encryptCipher = Cipher.getInstance(CIPHER_TYPE);
		encryptCipher.init(Cipher.ENCRYPT_MODE, key);

		decryptCipher = Cipher.getInstance(CIPHER_TYPE);
		decryptCipher.init(Cipher.DECRYPT_MODE, key);
	}
	
	/**
	 * 将byte数组转换为16进制值表示的字符串 
	 * @param bytes 需要转换的byte数组
	 * @return 转换后的字符串
	 * @throws Exception
	 */
	public static String bin2hex(byte[] bytes) throws Exception {
		int bytesLength = bytes.length;
		// 每个byte用两个字符才能表示，所以字符串的长度是数组长度的两倍
		StringBuffer sb = new StringBuffer(bytesLength * 2);
		for (int i = 0; i < bytesLength; i++) {
			int intTmp = bytes[i];
			// 把负数转换为正数
			while (intTmp < 0) {
				intTmp = intTmp + 256;
			}
			// 小于0F的数需要在前面补0
			if (intTmp < 16) {
				sb.append("0");
			}
			sb.append(Integer.toString(intTmp, 16));
		}
		return sb.toString();
	}

	/**
	 * 将表示16进制值的字符串转换为byte数组
	 * @param hexStr
	 *            需要转换的字符串
	 * @return 转换后的byte数组
	 * @throws Exception
	 */
	public static byte[] hex2bin(String hexStr) throws Exception {
		byte[] hexBytes = hexStr.getBytes();
		int iLen = hexBytes.length;

		// 两个字符表示一个字节，所以字节数组长度是字符串长度除以2
		byte[] result = new byte[iLen / 2];
		for (int i = 0; i < iLen; i = i + 2) {
			String strTmp = new String(hexBytes, i, 2);
			result[i / 2] = (byte) Integer.parseInt(strTmp, 16);
		}
		return result;
	}

	/**
	 * 加密字节数组
	 * 
	 * @param arrB
	 *            需加密的字节数组
	 * @return 加密后的字节数组
	 * @throws Exception
	 */
	public byte[] encrypt(byte[] arrB) throws Exception {
		return encryptCipher.doFinal(arrB);
	}

	/**
	 * 加密字符串
	 * 
	 * @param strIn
	 *            需加密的字符串 119. *
	 * @return 加密后的字符串
	 * @throws Exception
	 */
	public String encrypt(String strIn) throws Exception {
		return bin2hex(encrypt(strIn.getBytes()));
	}


	/**
	 * 解密字节数组
	 * 
	 * @param arrB
	 *            需解密的字节数组
	 * @return 解密后的字节数组
	 * @throws Exception
	 */
	public byte[] decrypt(byte[] arrB) throws Exception {
		return decryptCipher.doFinal(arrB);
	}

	/**
	 * 解密字符串
	 * 
	 * @param strIn
	 *            需解密的字符串
	 * @return 解密后的字符串
	 * @throws Exception
	 */
	public String decrypt(String strIn) throws Exception {
		return new String(decrypt(hex2bin(strIn)));
	}

	/**
	 * 从字符串生成密钥对象<br>
	 * 密钥所需的字节数组长度为8位 不足8位时后面补0，超出8位只取前8位
	 * @param bytes
	 *            构成该字符串的字节数组
	 * @return 生成的密钥
	 * @throws java.lang.Exception
	 */
	private Key generateKey(byte[] bytes) throws Exception {
		// 创建一个空的8位字节数组（默认值为0）
		byte[] arrB = new byte[8];

		// 将原始字节数组转换为8位
		for (int i = 0; i < bytes.length && i < arrB.length; i++) {
			arrB[i] = bytes[i];
		}

		// 生成密钥
		Key key = new javax.crypto.spec.SecretKeySpec(arrB, "DES");

		return key;
	}

	public static void main(String[] args) throws Exception {
		String str = "{\"passwd\":\"12345678\",\"phone\":\"13245678901\",\"identify\":\"479775\"}";
		DESUtil desSecurityUtil = new DESUtil();
		String enStr = desSecurityUtil.encrypt(str);
		System.out.println(enStr);
		System.out.println(desSecurityUtil.decrypt(enStr));

		DESUtil desSecurityUtils = new DESUtil("78!@#$25");
		String enStr1 = desSecurityUtils.encrypt(str);
		System.out.println(enStr1);
		System.out.println(desSecurityUtils.decrypt(enStr1));

	}
}
