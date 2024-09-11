import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

public class Main {
    public static void main(String[] args) {
        HashMap<Integer, byte[]> data = new HashMap<>();
//        String C1 = "";
//        String C2 = "";

        // Parameters
        int numRandomNumbers = 1000000;
        int numberOfBytes = 32;
        String outputFile = "Leak_Hash_random_numbers9.txt"; // Output file path

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

        try(BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            for (int i = 1; i <= numRandomNumbers; i++) {
                byte[] randomBytes = new byte[numberOfBytes];

                hashDRBG.generate(randomBytes, null, false);
                if(i < 57) {
                    data.put(i, randomBytes);
                }
                writer.write(bytesToBinaryString(randomBytes));
                writer.newLine();
            }
            System.out.println("Random numbers generated and saved to " + outputFile);
        }catch (IOException e){
            e.printStackTrace();
        }

        BackDoor door = new BackDoor();
        door.seedRecovery(data, numberOfBytes);

    }
    private static String bytesToBinaryString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }
}
