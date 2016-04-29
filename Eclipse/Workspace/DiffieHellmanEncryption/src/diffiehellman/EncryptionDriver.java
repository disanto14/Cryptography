package diffiehellman;

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
		String pText = args[1];
		String gText = args[2];
		String aText = args[3];
		String bText = args[4];
		BigInteger p = (new BigInteger(pText)).nextProbablePrime();
		int blockSize = encrypt? p.toByteArray().length - 1 : p.toByteArray().length;
		BigInteger g = new BigInteger(gText);
		BigInteger a = new BigInteger(aText);
		BigInteger gb = g.modPow(new BigInteger(bText), p);
		DiffieHellman dh = null;
		dh = new DiffieHellman(p, g, a, gb);
		
		System.out.println();
		String messageFileName = args[5];
		String resultFileName = args[6];
		try {
			Path messagePath = Paths.get(messageFileName);
			byte[] messageBytes = Files.readAllBytes(messagePath);
			
			FileOutputStream resultStream = new FileOutputStream(resultFileName);
			
			ArrayList<Byte> resultBytes = new ArrayList<Byte>();
			for (int i = 0; i < messageBytes.length; i += blockSize) {
				byte[] block;
				if (i + blockSize <= messageBytes.length)
					block = Arrays.copyOfRange(messageBytes, i, i + blockSize);
				else {
					block = Arrays.copyOfRange(messageBytes, i, messageBytes.length);
				}
				for (byte b : block) {
					System.out.print(formatByte(b) + " ");
				}
				System.out.println();
				byte[] resultBlock;
				if (encrypt) {
					resultBlock = new byte[blockSize + 1];
					byte[] cryptotext = dh.encrypt(block);
					if (cryptotext.length < blockSize + 1) {
						int difference = blockSize + 1 - cryptotext.length;
						for (int j = 0; j < cryptotext.length; j++) {
							resultBlock[difference + j] = cryptotext[j];
						}
					} else {
						resultBlock = cryptotext;
					}
				}
				else {
					resultBlock = dh.decrypt(block);
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
