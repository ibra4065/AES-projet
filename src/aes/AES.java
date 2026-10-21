package aes;

import java.security.SecureRandom;

public class AES {
	private final int taille_bloc = 128;
	private static final int[] Rcon = {
		    0x00, // Indice 0 : Non utilisé (ou égal à 0)
		    0x01, // Rcon[1] (Tour 1)
		    0x02, // Rcon[2] (Tour 2)
		    0x04, // Rcon[3] ...
		    0x08, // Rcon[4]
		    0x10, // Rcon[5]
		    0x20, // Rcon[6]
		    0x40, // Rcon[7]
		    0x80, // Rcon[8]
		    0x1B, // Rcon[9]
		    0x36  // Rcon[10] (Tour 10)
		};
	// S-Box officielle d'AES (Chiffrement)
	private static final int[][] sBox = {
	    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
	    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
	    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
	    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
	    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
	    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
	    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
	    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
	    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
	    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
	    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
	    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
	    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
	    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
	    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
	    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
	};

	// S-Box Inverse officielle d'AES (Déchiffrement)
	private static final int[][] sBoxInv = {
	    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
	    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
	    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
	    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
	    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
	    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
	    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
	    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
	    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
	    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
	    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
	    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
	    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
	    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
	    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
	    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
	};
	
	private final int[][] matriceCoeff = {
	        {2, 3, 1, 1}, // Ligne pour calculer la case 0 d'une colonne
	        {1, 2, 3, 1}, // Ligne pour calculer la case 1 d'une colonne
	        {1, 1, 2, 3}, // Ligne pour calculer la case 2 d'une colonne
	        {3, 1, 1, 2}  // Ligne pour calculer la case 3 d'une colonne
	    };
	
	private int taille_cle_maitre;
	private int NK;
	private int nb_ronde;
    private int[][] master_Key;          // Clé maîtresse sous forme de tableau multidimensionnel
    private int[][][] keys;
    private int[][][] states;
    
    
   
    // === CONSTRUCTEUR DYNAMIQUE ===
    public AES(int taille_cle_maitre) {
        if (taille_cle_maitre != 128 && taille_cle_maitre != 192 && taille_cle_maitre != 256) {
            throw new IllegalArgumentException("La taille de la clé doit être 128, 192 ou 256 bits.");
        }
        
        this.taille_cle_maitre = taille_cle_maitre;
        
        // Détermination du nombre de rondes selon les spécifications AES
        if (taille_cle_maitre == 128) this.nb_ronde = 10;
        else if (taille_cle_maitre == 192) this.nb_ronde = 12;
        else this.nb_ronde = 14;

        // La master_Key prend 4 lignes et Nk colonnes (Nk = 4, 6 ou 8)
        this.NK = taille_cle_maitre / 32; 
        this.master_Key = new int[4][NK];
        
        // Initialisation de toutes les clés de tour nécessaires : (nb_ronde + 1) matrices de 4x4
        this.keys = new int[this.nb_ronde + 1][4][4];
        
        
        genereMasterKey();
        createKeys();
        		
    }
    
    public String chiffrement(String message) {
    	int nbBlocs = (message.length() / 16) + 1;
        this.states = new int[nbBlocs][4][4];
        
        int tab[] = bourrage(stringToBits(message));
        int[][][] tablocs = decoupage_en_blocs(tab);
        for (int i=0 ; i<tablocs.length;i++) {
        	int[][] state = states[i];
        	addRoundKey(state, 0);
        	for (int tour = 1; tour < this.nb_ronde; tour++) {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, tour); // Utilise la clé spécifique à ce tour
            }
        	// Dernier tour (sans MixColumns)
            subBytes(state);
            shiftRows(state);
            addRoundKey(state, this.nb_ronde);
        }
        int[] resultatBits = recollage_des_blocs(this.states);
        return "";
        //return bitsToString(resultatBits, nbBlocs);
        
    }
    
    public static int[] stringToBits(String message) {
        int[] tabbytes = new int[message.length() * 8];
        
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            
            // On force la chaîne binaire à faire TOUJOURS 8 caractères (ajoute des '0' au début)
            String bits = String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0');
            
            // On parcourt TOUJOURS les 8 caractères de la chaîne fixe
            for (int j = 0; j < 8; j++) {
                // bits.charAt(j) donne le caractère '0' ou '1'. 
                // En soustrayant '0', on le convertit en entier 0 ou 1.
                tabbytes[(i * 8) + j] = bits.charAt(j) - '0';
            }
        }
        return tabbytes;
    }
    // probleme a regler ici pour la methode chiffrement 
    public static String bitsToString(int[] blocs) {
        StringBuilder message = new StringBuilder();

        for (int i = 0; i < blocs.length; i += 8) {
            int valeur = 0;

            for (int j = 0; j < 8; j++) {
                valeur = (valeur << 1) | blocs[i + j];
            }

            message.append((char) valeur);
        }

        return message.toString();
    }
    
    public void genereMasterKey() {
        // 1. On utilise un générateur de nombres aléatoires sécurisé
        SecureRandom random = new SecureRandom();
        
        // 2. On récupère dynamiquement le nombre de colonnes nécessaires (4, 6 ou 8)
        
        
        // 3. On remplit chaque case de notre matrice master_Key
        for (int col = 0; col < NK; col++) {
            for (int row = 0; row < 4; row++) {
                // random.nextInt(256) génère un entier aléatoire compris entre 0 et 255
            	int r = random.nextInt(256);;
                this.master_Key[row][col] = r;
                
            }
        }
    }
    
    private void createKeys() {
        int nombreMots = 4 * (nb_ronde + 1);
        int[][] w = new int[nombreMots][4];

        // 1. Copier la clé maître dans les premiers mots
        for (int i = 0; i < NK; i++) {
            for (int j = 0; j < 4; j++) {
                w[i][j] = master_Key[j][i];
            }
        }

        // 2. Générer les mots suivants
        for (int i = NK; i < nombreMots; i++) {
            int[] temp = w[i - 1].clone();

            if (i % NK == 0) {
                // RotWord
                temp = rotWord(temp);

                // SubWord
                temp = subWord(temp);

                // XOR avec Rcon
                temp[0] ^= Rcon[i / NK];

            } else if (NK == 8 && i % NK == 4) {
                // Étape supplémentaire pour AES-256
                temp = subWord(temp);
            }

            // w[i] = w[i - NK] XOR temp
            for (int j = 0; j < 4; j++) {
                w[i][j] = w[i - NK][j] ^ temp[j];
            }
        }

        // 3. Ranger les mots dans les clés de ronde
        for (int ronde = 0; ronde <= nb_ronde; ronde++) {
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    keys[ronde][row][col] =
                        w[ronde * 4 + col][row];
                }
            }
        }
    }
    
    private int[] subWord(int[] mot) {
        int[] resultat = new int[4];

        for (int i = 0; i < 4; i++) {
            int ligne = (mot[i] >> 4) & 0x0F;
            int colonne = mot[i] & 0x0F;

            resultat[i] = sBox[ligne][colonne];
        }

        return resultat;
    }
    
    private int[] rotWord(int[] mot) {
        return new int[] {
            mot[1], mot[2], mot[3], mot[0]
        };
    }
    
    private void addRoundKey(int[][] state, int tour) {
        // On parcourt l'intégralité de la matrice 4x4 (lignes et colonnes)
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                // Opération XOR entre l'octet du texte (state) et l'octet de la clé du tour actuel
                state[row][col] = state[row][col] ^ this.keys[tour][row][col];
            }
        }
    }

    
    protected  int[] bourrage(int[] tabBits) {
        // 1. Calcul du nombre d'octets actuellement présents dans le tableau de bits
        int octetsActuels = tabBits.length / 8;
        
        // 2. Calcul du nombre d'octets manquants pour atteindre le prochain multiple de 16
        int octetsManquants = 16 - (octetsActuels % 16);
        
        // 3. Calcul de la taille finale en bits (ancienne taille + bits de bourrage)
        int bitsManquants = octetsManquants * 8;
        int[] tableauBourre = new int[tabBits.length + bitsManquants];
        
        // 4. Copie des bits d'origine (le message en binaire) dans le nouveau tableau
        System.arraycopy(tabBits, 0, tableauBourre, 0, tabBits.length);
        
        // 5. Ajout du bourrage : on convertit la valeur 'octetsManquants' en paquets de 8 bits
        int indexInsertion = tabBits.length;
        for (int i = 0; i < octetsManquants; i++) {
            for (int j = 0; j < 8; j++) {
                // Extraction bit par bit de la valeur numérique (du bit fort au bit faible)
                tableauBourre[indexInsertion++] = (octetsManquants >> (7 - j)) & 1;
            }
        }
        
        return tableauBourre;
    }

    
    
    public int[][][] decoupage_en_blocs(int[] tabBitsBourre) {
        // 1. Calculer le nombre de blocs de 128 bits disponibles dans le tableau
        int nbBlocs = tabBitsBourre.length / 128;
        
        // 2. Initialiser le tableau tridimensionnel qui va contenir toutes les matrices 4x4
        int[][][] mesBlocsStates = new int[nbBlocs][4][4];
        
        int indexBits = 0;

        // 3. Parcourir chaque bloc de message
        for (int b = 0; b < nbBlocs; b++) {
            // L'AES remplit chaque matrice bloc par colonne, puis par ligne
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    
                    // On lit 8 bits consécutifs pour reconstruire l'entier de l'octet (0 à 255)
                    int valeurOctet = 0;
                    for (int bit = 0; bit < 8; bit++) {
                        // On utilise le décalage à gauche et le OU binaire qu'on a vu ensemble
                        valeurOctet = (valeurOctet << 1) | tabBitsBourre[indexBits++];
                    }
                    
                    // On enregistre l'octet décimal dans la bonne case de la matrice du bloc actuel
                    mesBlocsStates[b][row][col] = valeurOctet;
                }
            }
        }
        
        // 4. On affecte ce résultat directement à l'attribut global de la classe
        this.states = mesBlocsStates;
        
        // 5. On retourne le tableau multidimensionnel comme demandé par votre énoncé
        return mesBlocsStates;
    }
    
    private int[] recollage_des_blocs(int[][][] blocs) {
        // Chaque bloc contient 16 octets, soit 128 bits
        int[] tabBits = new int[blocs.length * 128];

        int indexBits = 0;

        // Parcourir chaque bloc
        for (int b = 0; b < blocs.length; b++) {

            // Parcourir les colonnes, comme dans decoupage_en_blocs()
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {

                    int octet = blocs[b][row][col];

                    // Convertir l'octet en 8 bits, du plus significatif au moins significatif
                    for (int bit = 7; bit >= 0; bit--) {
                        tabBits[indexBits++] = (octet >> bit) & 1;
                    }
                }
            }
        }

        return tabBits;
    }
    
    private  int[] xor(int[] tab1, int[] tab2) {
        // 1. Vérification de sécurité : les deux tableaux doivent obligatoirement avoir la même taille
        if (tab1.length != tab2.length) {
            throw new IllegalArgumentException("Les deux tableaux doivent avoir exactement la même taille.");
        }

        // 2. Création du tableau qui va contenir le résultat
        int[] resultat = new int[tab1.length];

        // 3. Application de l'opérateur XOR (^) sur chaque case
        for (int i = 0; i < tab1.length; i++) {
            resultat[i] = tab1[i] ^ tab2[i];
        }

        // 4. On retourne le tableau final
        return resultat;
    }
    private  void subBytes(int[][] state) {
        // On parcourt l'intégralité de la matrice 4x4 (lignes et colonnes)
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                int valeur = state[row][col];
                
                // 1. On isole les 4 bits de gauche (poids fort) pour trouver la ligne de la S-Box
                // L'opérateur >> 4 décale de 4 crans à droite. Le & 0x0F assure qu'on ne garde que 4 bits.
                int indexLigne = (valeur >> 4) & 0x0F;
                
                // 2. On isole les 4 bits de droite (poids faible) pour trouver la colonne de la S-Box
                // Le masque & 0x0F efface les bits de gauche et ne garde que les 4 bits de droite.
                int indexColonne = valeur & 0x0F;
                
                // 3. On remplace l'octet d'origine par la valeur trouvée dans la sBox
                state[row][col] = sBox[indexLigne][indexColonne];
            }
        }
    }
    private void shiftRows(int[][] state) {
        // Variable temporaire pour stocker une ligne pendant qu'on la décale
        int[] temp = new int[4];

        // --- LIGNE 1 : Décalage de 1 case vers la gauche ---
        temp[0] = state[1][1];
        temp[1] = state[1][2];
        temp[2] = state[1][3];
        temp[3] = state[1][0]; // Le premier passe à la fin
        System.arraycopy(temp, 0, state[1], 0, 4);

        // --- LIGNE 2 : Décalage de 2 cases vers la gauche ---
        temp[0] = state[2][2];
        temp[1] = state[2][3];
        temp[2] = state[2][0];
        temp[3] = state[2][1];
        System.arraycopy(temp, 0, state[2], 0, 4);

        // --- LIGNE 3 : Décalage de 3 cases vers la gauche (revient à 1 case à droite) ---
        temp[0] = state[3][3];
        temp[1] = state[3][0];
        temp[2] = state[3][1];
        temp[3] = state[3][2];
        System.arraycopy(temp, 0, state[3], 0, 4);
    }

    private int deux_a(int octet) {
        // 1. On vérifie si le bit le plus à gauche vaut 1 (0x80 en hexadécimal vaut 10000000 en binaire)
        int dépassement = octet & 0x80;
        
        // 2. On décale l'octet d'un cran vers la gauche
        int resultat = (octet << 1) & 0xFF; // Le & 0xFF assure qu'on reste strictement sur 8 bits
        
        // 3. Si le bit de gauche valait 1, on applique le XOR correctif avec 0x1B
        if (dépassement != 0) {
            resultat = resultat ^ 0x1B;
        }
        
        return resultat;
    }
    private int trois_a(int octet) {
        // Multiplier par 3 = (Multiplier par 2) XOR (Multiplier par 1)
        return deux_a(octet) ^ octet;
    }
    
    
 // === METHODES MULTIPLICATION POUR LE DECHIFFREMENT ===

 // Multiplier par 9 = (((x * 2) * 2) * 2) ^ x   =>  8x ^ x = 9x
    private int neuf_a(int octet) {
    	int fois2 = deux_a(octet);
    	int fois4 = deux_a(fois2);
    	int fois8 = deux_a(fois4);
    	return fois8 ^ octet;
    }

    // Multiplier par 11 = (((x * 2) * 2) ^ x) * 2 ^ x  =>  ((4x ^ x) * 2) ^ x = 8x ^ 2x ^ x = 11x
    private int onze_a(int octet) {
    	int fois2 = deux_a(octet);
    	int fois4 = deux_a(fois2);
    	int fois8 = deux_a(fois4);
    	return fois8 ^ fois2 ^ octet;
    }

    // Multiplier par 13 = (((x * 2) ^ x) * 2 * 2) ^ x  =>  ((2x ^ x) * 4) ^ x = 8x ^ 4x ^ x = 13x
    private int treize_a(int octet) {
    	int fois2 = deux_a(octet);
    	int fois4 = deux_a(fois2);
    	int fois8 = deux_a(fois4);
    	return fois8 ^ fois4 ^ octet;
    }

    // Multiplier par 14 = (((x * 2) ^ x) * 2 ^ x) * 2  =>  ((2x ^ x) * 2 ^ x) * 2 = 8x ^ 4x ^ 2x = 14x
    private int quatorze_a(int octet) {
    	int fois2 = deux_a(octet);
    	int fois4 = deux_a(fois2);
    	int fois8 = deux_a(fois4);
    	return fois8 ^ fois4 ^ fois2;
    }

 // Étape Chiffrement : Multiplie 4 coefficients par 4 octets d'une colonne
    private int prodAu(int[] coefficients, int[] colonne) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int temp = 0;
            // On applique la bonne fonction multiplicatrice selon le coefficient
            if (coefficients[i] == 1)      temp = colonne[i];
            else if (coefficients[i] == 2) temp = deux_a(colonne[i]);
            else if (coefficients[i] == 3) temp = trois_a(colonne[i]);
            
            // Accumulation par XOR (symbole ^)
            res = res ^ temp;
        }
        return res;
    }

    // Étape Déchiffrement : Utile pour prodAuInv (coefficients 9, 11, 13, 14)
    private int prodAuInv(int[] coefficients, int[] colonne) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int temp = 0;
            if (coefficients[i] == 9)       temp = neuf_a(colonne[i]);
            else if (coefficients[i] == 11) temp = onze_a(colonne[i]);
            else if (coefficients[i] == 13) temp = treize_a(colonne[i]);
            else if (coefficients[i] == 14) temp = quatorze_a(colonne[i]);
            
            res = res ^ temp;
        }
        return res;
    }
    
    private void mixColumns(int[][] state) {
        

        // 2. On traite la matrice state colonne par colonne (de 0 à 3)
        for (int col = 0; col < 4; col++) {
            // Extraction des 4 octets de la colonne actuelle du state
            int[] colonneActuelle = {
                state[0][col],
                state[1][col],
                state[2][col],
                state[3][col]
            };

            // Tableau temporaire pour stocker les 4 nouveaux octets de cette colonne
            int[] nouvelleColonne = new int[4];

            // Pour chaque case de la colonne, on applique une ligne de coefficients différente
            for (int row = 0; row < 4; row++) {
                nouvelleColonne[row] = prodAu(matriceCoeff[row], colonneActuelle);
            }

            // 3. On réinjecte la colonne entièrement calculée dans la matrice state d'origine
            for (int row = 0; row < 4; row++) {
                state[row][col] = nouvelleColonne[row];
            }
        }
    }


    //exemple de chifrement methode 
    /*public int[][] chiffrer(int[][] state) {
        // Tour initial
        addRoundKey(state, 0); 
        
        // Tours intermédiaires (1 à nb_ronde - 1)
        for (int tour = 1; tour < this.nb_ronde; tour++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, tour); // Utilise la clé spécifique à ce tour
        }
        
        // Dernier tour (sans MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, this.nb_ronde);
        
        return state; // Contient maintenant le texte chiffré !
    }*/
    
}
