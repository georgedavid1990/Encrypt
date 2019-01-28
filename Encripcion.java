package solidappservice.co.com.colanta.tools.encripcion;


import android.util.Base64;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encripcion {

	private static Encripcion singleton;

	public static Encripcion getInstance() {
		if (singleton == null) {
			try {
				synchronized (Encripcion.class) {
					if (null == singleton) {
						singleton = new Encripcion();
					}
				}
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
		return singleton;
	}

	//indexes from 0 to 90
    private static final char[] alphabet =
            new char[] {
	                'a', 'A', 'z', 'Z', '1', '2', '@',
                    'b', 'B', 'y', 'Y', '3', '4', ']',
                    'c', 'C', 'x', 'X', '5', '6', '[',
                    'd', 'D', 'w', 'W', '7', '8', '{',
                    'e', 'E', 'v', 'V', '9', '0', '}',
                    'f', 'F', 't', 'T', ',', '.', '¡',
                    'g', 'G', '¿', '?', '*', '!', ':',
                    'h', 'H', 's', 'S', '-', '_', '|',
                    'i', 'I', 'r', 'R', '+', '#', ';',
                    'j', 'J', 'q', 'Q', '$', '%', '^',
                    'k', 'K', 'p', 'P', '&', '(', ' ',
                    'l', 'L', 'o', 'O', ')', '=', '`',
                    'm', 'M', 'n', 'N', '<', '>', '/'};

    /**
     * refer to https://pdfs.semanticscholar.org/e6b8/9b406fe58ccd7f5886ab5ce26b05e101812a.pdf
     * @param word to encrypt
     * @return encrypted  word
     */
    public String encrypt(String word){

        //1. Convert all characters of input plaintext into its ASCII values
        int[] asciiValues = generateAsciiArray(word);

        //2. Min value from ascii array
        int minValue = minValueFrom(asciiValues);

        //3. Now Perform modulus operation on each value of asciiValues by minValue
        // and store result into modArray.
        int[] valModArray = generateModeArray(asciiValues, minValue);
        //3.1 Calclate quotient of dividing asciiValues by minValue
        int[] valQuotientArray = generateQuotientArray(asciiValues, minValue);

        //4. Automatically generate a key having length equal to
        //the length of plaintext and store it to keyChar array.
        char[] keyCharArray = generateCharKey(word.length());

        //5. Convert all the character from keyChar array into
        //ASCII value and save it to asciiKey array.
        int[] asciiKeyArray = generateAsciiArray(keyCharArray);

        //6. Find minimum value minKey from asciiKey array.
        int minKey = minValueFrom(asciiKeyArray);

        //7. Perform modulus operation on each value of asciiKey
        //by minKey and store result into keyMod array.
        int[] keyModArray = generateModeArray(asciiKeyArray, minKey);

        //8. Now add keyMod array into valMod array to form
        //encrypted key encKey.
        int[] encKeyArray = sum(valModArray, keyModArray);

        //9. Now add minValue to each value of encKey array to
        //get cipher text of plaintext.
        int[] asciiCipher = sum(encKeyArray, minValue);

        //10. Convert encKeyArray into text
        StringBuilder encKeyText = new StringBuilder();
        for (int mod : encKeyArray) {
            encKeyText.append(alphabet[mod]);
        }

        //11. Convert valModArray into text
        StringBuilder modText = new StringBuilder();
        for (int mod : valModArray) {
            modText.append(alphabet[mod]);
        }

        //12. Convert valQuotientArray int text
        StringBuilder quotientText = new StringBuilder();
        for (int q : valQuotientArray) {
            quotientText.append(alphabet[q]);
        }

        //13. Convert encKeyText, modText and quotientText into ascii int codes
        int[] encKeyTextChars = generateAsciiArray(encKeyText.toString());
        int[] valModTextChars = generateAsciiArray(modText.toString());
        int[] valQuotientTextChars = generateAsciiArray(quotientText.toString());

        //14. Append encrypted text with encKeyTextChars and encKeyTextChars ascii integer values
        int[] finalAsciiSet = append(asciiCipher, encKeyTextChars);
        finalAsciiSet = append(finalAsciiSet, valModTextChars);
        finalAsciiSet = append(finalAsciiSet, valQuotientTextChars);

        return generateText(finalAsciiSet);
    }

    public String decrypt(String cipherText){

        int length = cipherText.length() / 4;
        char[] cipherTextArray = new char[length];
        char[] encKeyArray = new char[length];
        char[] valModArray = new char[length];
        char[] valQuotientArray = new char[length];

        int end2 = (length*2);
        int end3 = (length*3);

        char[] charArray = cipherText.toCharArray();
        System.arraycopy(charArray, 0, cipherTextArray, 0, length);
        System.arraycopy(charArray, length, encKeyArray, 0, length);
        System.arraycopy(charArray, end2, valModArray, 0, length);
        System.arraycopy(charArray, end3, valQuotientArray, 0, length);

        //1. Convert all characters of cipherText into its ASCII
        //values and store it in decArray.
        int[] decArray = generateAsciiArray(cipherTextArray);

        //2. Convert all characters of encKeyArray into its ASCII values
        int[] encKeyAsciiArray = generateAscciArrayFromAlphabet(encKeyArray);

        //3. Convert all characters of valModArray into its ASCII values
        int[] valModAsciiArray = generateAscciArrayFromAlphabet(valModArray);

        //4.
        int[] valQuotientAsciiArray = generateAscciArrayFromAlphabet(valQuotientArray);

        //5. Now subtract value of final encrypted key encKey array
        //from value of decArray.
        int[] difference = subtract(decArray, encKeyAsciiArray);

        //6. Multiply valQuotientArray value by difference array value
        int[] fittedDifference = multiply(difference, valQuotientAsciiArray);

        //7. Add difference and charMod to generate original plaintext.
        int[] originalAsciiSet = sum(fittedDifference, valModAsciiArray);

        return generateText(originalAsciiSet);

    }

    private int[] generateAscciArrayFromAlphabet(char[] valModArray) {
        int[] output = new int[valModArray.length];
        int pos = 0;
        for (char actualChar : valModArray) {
            for (int y = 0; y < alphabet.length; y++) {
                char alphabetChar = alphabet[y];
                if (alphabetChar == actualChar) {
                    output[pos] = y;
                    pos++;
                    break;
                }
            }
        }
        return output;
    }

	  private int random(int min, int max){
        return min + (int) (Math.random() * ((max - min) + 1));
    }

    private int[] generateAsciiArray(String input){
        int[] output = new int[input.length()];
        char[] source = input.toCharArray();
        for (int i = 0; i < source.length; i++) {
            output[i] = (int)source[i];
        }
        return output;
    }

    private int[] generateAsciiArray(char[] input){
        int[] output = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (int)input[i];
        }
        return output;
    }

    private int[] generateModeArray(int[] input, int modulus){
        int[] output = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = input[i]%modulus;
        }
        return output;
    }

    private int[] generateQuotientArray(int[] input, int divisor){
        int[] output = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = input[i]/divisor;
        }
        return output;
    }

    private char[] generateCharKey(int length){
        char[] output = new char[length];
        for (int i = 0; i < length; i++) {
            output[i] = alphabet[random(0, 90)];
        }
        return output;
    }

    private int[] sum(int[] a, int[] b){
        int[] output = new int[a.length];
        for(int i = 0; i < output.length; i++){
            output[i] = a[i] + b[i];
        }
        return output;
    }

    private int[] subtract(int[] a, int[] b){
        int[] output = new int[a.length];
        for(int i = 0; i < output.length; i++){
            output[i] = a[i] - b[i];
        }
        return output;
    }

    private int[] subtract(int[] a, int b){
        int[] output = new int[a.length];
        for(int i = 0; i < output.length; i++){
            output[i] = a[i] - b;
        }
        return output;
    }

    private int[] sum(int[] a, int b){
        int[] output = new int[a.length];
        for(int i = 0; i < output.length; i++){
            output[i] = a[i] + b;
        }
        return output;
    }

    private int[] multiply(int[] a, int[] b){
        int[] output = new int[a.length];
        for(int i = 0; i < output.length; i++){
            output[i] = a[i] * b[i];
        }
        return output;
    }

    private int[] append(int[] a, int[] b){

        int length = a.length + b.length;

        int[] result = new int[length];
        int pos = 0;
        for (int element : a) {
            result[pos] = element;
            pos++;
        }

        for (int element : b) {
            result[pos] = element;
            pos++;
        }

        return result;
    }

    private String generateText(int[] ascii){
        StringBuilder sb = new StringBuilder();
        for (int character : ascii) {
            sb.append((char) character);
        }
        return sb.toString();
    }

    private int minValueFrom(int[] input){
        int minValue = input[0];
        for (int i = 1; i < input.length; i++){
            if(input[i] < minValue){
                minValue = input[i];
            }
        }
        return minValue;
    }

	//region AES Encription
	private static final String ALGORITHM = "AES";
	private static final byte[] keyValue =
			new byte[] { 'L', 't', 'x', 'V', 'a', 'a', 'W', 'q', 'x', 'o', 'c', 'S', 'z', 'R', 'h', 'j' };

	public String encriptar_aes(String valueToEnc) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encValue = c.doFinal(valueToEnc.getBytes());
		String encryptedValue = Base64.encodeToString(encValue, Base64.DEFAULT);//new BASE64Encoder().encode(encValue);
		return encryptedValue;
	}

	public String desencriptar_aes(String encryptedValue) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = Base64.decode(encryptedValue, Base64.DEFAULT);//new BASE64Decoder().decodeBuffer(encryptedValue);
		byte[] decValue = c.doFinal(decordedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}

	private static Key generateKey(){
		return new SecretKeySpec(keyValue, ALGORITHM);
	}
	//endregion

}
