import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {

        String C1 = "";
        String C2 = "";

        // Parameters
        int numRandomNumbers = 56;
        int numberOfBytes = 32;
        String outputFile = "Leak_Hash_random_numbers.txt"; // Output file path

        // Step 1: Create a SecureRandom instance for entropy
        SecureRandom secureRandom = new SecureRandom();

        // Step 2: Create an EntropySourceProvider
        EntropySourceProvider entropySourceProvider = new BasicEntropySourceProvider(secureRandom, true);

        // Step 3: Create an EntropySource with 256-bit security strength
        EntropySource entropySource = entropySourceProvider.get(256);

        HashDRBG hashDRBG = new HashDRBG(
                new SHA256Digest(),
                256,
                entropySource,
                null,
                null
        );

        byte[] randomBytes = new byte[numberOfBytes];
        for (int i = 1; i <= numRandomNumbers; i++) {
            hashDRBG.generate(randomBytes, null, false);
            if(i % 2 != 0){
                for (int j = 6; j < numberOfBytes; j+=7) {
                    C1 = C1 + randomBytes[j] + " ";
                }
            }else{
                for (int j = 6; j < numberOfBytes; j+=7) {
                    C2 = C2 + randomBytes[j] + " ";
                }
            }
            System.out.println(Arrays.toString(randomBytes));
        }
        System.out.println("recovered C1: " + C1);
        System.out.println("recovered C2: " + C2);
    }
    private static String bytesToBinaryString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }
}
