import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;

public class BackDoor {
    private BigInteger x = new BigInteger("109894458244908029220853813287316938790973239461598539959692282550118664565962941952182043700730446765400752803860997178803668450067213417012023035364938272467001792411071613310209012494285628470208546600256785119759862783627897775557809871932238171565259002163454856180");
    private BigInteger p = new BigInteger("372237540010079469245503495827942559243112358851042997529885562204687557082280361998968495303979024919107357688890920968493650209817944082992285485546224121721928289497490229726351292651073520663573779035633025586325811448006277217747030673205095056286824454158901848027");
    private byte[] recoveredSeed;
    private byte[] C1 = new byte[112];
    private int C1_counter = 0;
    private byte[] C2 = new byte[112];
    private int C2_counter = 0;

    private void secretRecovery(HashMap<Integer, byte[]> data, int numberOfBytes){
        // The number of bytes leaked per number
        int bytePerNumber = (numberOfBytes/7);
        // The number of required  random numbers to guess the seed
        int requiredNumbers = (112/bytePerNumber)*2;

        for (int i = 1; i <= requiredNumbers; i++) {
            if (i % 2 != 0){
                for (int j = 6; j < numberOfBytes; j+=7) {
                    if(C1_counter < 112) {
                        C1[C1_counter] = data.get(i)[j];
                        C1_counter++;
                    }
                }
            }else{
                for (int j = 6; j < numberOfBytes; j+=7) {
                    if (C2_counter < 112){
                        C2[C2_counter] = data.get(i)[j];
                        C2_counter++;
                    }
                }
            }
        }


    }

    public void seedRecovery(HashMap<Integer, byte[]> data, int numberOfBytes){
        // first find our secrets
        secretRecovery(data, numberOfBytes);
        // just for log +++++++++++++++++++++++++
        System.out.println("recovered C1:");
        System.out.println(Arrays.toString(C1));

        System.out.println("recovered C2:");
        System.out.println(Arrays.toString(C2));
        // ++++++++++++++++++++++++++++++++++++++
        // Use decryption algorithm
        BigInteger I_C1 = new BigInteger(C1);
        BigInteger I_C2 = new BigInteger(C2);
        // Compute shared secret s = c1^x mod p
        BigInteger s = I_C1.modPow(x, p);
        // Compute modular inverse of s mod p
        BigInteger sInv = s.modInverse(p);
        // Recover message m = c2 * sInv mod p
        recoveredSeed = I_C2.multiply(sInv).mod(p).toByteArray();
        System.out.println("recovered seed:");
        System.out.println(Arrays.toString(recoveredSeed));

    }


}
