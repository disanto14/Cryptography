package ellipticcurve;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;

public class EncryptionDriver {

	public static void main(String[] args) throws Exception {
		boolean encrypt = !args[0].equals("--d");
		ECC ecc = new ECC(new BigInteger("45678"), new BigInteger("12345"), new BigInteger("32416190071"), new BigInteger("12"), new BigInteger("33"));
		int blockSize = encrypt? ecc.encryptBlockSize() : ecc.decryptBlockSize();
		
		System.out.println();
		String messageFileName = args[1];
		String resultFileName = args[2];
		try {
			Path messagePath = Paths.get(messageFileName);
			byte[] messageBytes = Files.readAllBytes(messagePath);
			
			FileOutputStream resultStream = new FileOutputStream(resultFileName);
			
			ArrayList<Byte> resultBytes = new ArrayList<Byte>();
			for (int i = 0; i < messageBytes.length; i += blockSize) {
				boolean lastBlock = false;
				byte[] block;
				if (i + blockSize <= messageBytes.length)
					block = Arrays.copyOfRange(messageBytes, i, i + blockSize);
				else {
					lastBlock = true;
					block = Arrays.copyOfRange(messageBytes, i, messageBytes.length);
				}
				for (byte b : block) {
					System.out.print(formatByte(b) + " ");
				}
				System.out.println();
				byte[] resultBlock;
				if (encrypt) {
					resultBlock = new byte[ecc.decryptBlockSize()];
					byte[] cryptotext = ecc.encrypt(block);
					if (cryptotext.length < ecc.decryptBlockSize() && !lastBlock) {
						for (int j = 0; j < cryptotext.length; j++) {
							resultBlock[j + ecc.decryptBlockSize() - cryptotext.length] = cryptotext[j];
						}
					} else {
						resultBlock = cryptotext;
					}
				}
				else {
					resultBlock = new byte[ecc.encryptBlockSize()];
					byte[] plaintext = ecc.decrypt(block);
					if (plaintext.length < ecc.encryptBlockSize() && !lastBlock) {
						for (int j = 0; j < plaintext.length; j++) {
							resultBlock[j + ecc.decryptBlockSize() - plaintext.length] = plaintext[j];
						}
					} else {
						resultBlock = plaintext;
					}
				}
				for (int j = 0; j < resultBlock.length; j++) {
					resultBytes.add(new Byte(resultBlock[j]));
					System.out.print(formatByte(resultBlock[j]) + " ");
				}
				System.out.println("\n");
				
			}
			
			try {
				byte[] result = new byte[resultBytes.size()];
				for (int i = 0; i < result.length; i++)
				    result[i] = resultBytes.get(i).byteValue();
				resultStream.write(result);
			}
			finally {
				resultStream.close();
			}			
		}
		catch (Exception e) {
			throw e;
		}
	}
	
	public static String formatByte(byte b) {
		String bs = "00000000" + Integer.toBinaryString(b);
		return bs.substring(bs.length() - 8);
	}
}
