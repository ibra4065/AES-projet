package aes;

import java.util.Arrays;

public class TestAES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String m = "htjrfuygtfoksevbzudjudsu";
		System.out.println(Arrays.toString(AES.stringToBits(m)));
		System.out.println(16^15);
	}

}
