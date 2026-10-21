package aes;

import java.util.Arrays;

public class TestAES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String m = "htjrfuygtfoksevbzudjudsu";
		System.out.println(Arrays.toString(AES.stringToBits(m)));
		System.out.println(16^15);
		//AES aes = new AES(128, "ABC");

	    /*int[] bits = AES.stringToBits("ABC");
	    int[] resultat = aes.bourrage(bits);

	    System.out.println("Taille initiale : " + bits.length + " bits");
	    System.out.println("Taille finale : " + resultat.length + " bits");
	    System.out.println("Nombre d'octets : " + resultat.length / 8);

	    System.out.print("Derniers octets : ");

	    for (int i = resultat.length - 16; i < resultat.length; i += 8) {
	        int valeur = 0;

	        for (int j = 0; j < 8; j++) {
	            valeur = (valeur << 1) | resultat[i + j];
	        }

	        System.out.print(valeur + " ");
	    }*/
	}

}
