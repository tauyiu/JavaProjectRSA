//reference list: lecture slides, tutorials, textbooks, stack overflow
package com.company;

import java.io.*;
import java.math.BigInteger;

public class Main3 {

    public static void main(String[] args) throws IOException
    {
        Question3 q3 = new Question3();
        System.out.println("RSA Algorithm\nEnter user input(x), for up to 2^(x) value of primes p and q\nLarger input requires longer time to compute [e.g. 1024 bits takes around 10 seconds(depends on hardware too I suppose)]");
        int userNumInput = q3.getInput();   //get user input for bits length for p and q, (65-1024)
        BigInteger p = q3.numberGenerator(userNumInput);
        while(q3.primeTest(p)!= true)   //random generate until a prime number, p is produced
        {
            p = q3.numberGenerator(userNumInput);
            System.out.println("Number generated: "+ p + " ,Bit length: " +p.bitLength());
        }

        BigInteger q = q3.numberGenerator(userNumInput);
        while(q3.primeTest(q)!= true)   //random generate until a prime number, q is produced
        {
            q = q3.numberGenerator(userNumInput);
            System.out.println("Number generated: "+ q + " ,Bit length: " +q.bitLength());
        }

        System.out.println("p: "+ p + " ,Bit length: " +p.bitLength() +", prime number.");
        System.out.println("q: "+ q + " ,Bit length: " +q.bitLength()+", prime number\n");
        System.out.println("2^64: "+ BigInteger.TWO.pow(64));
        System.out.println(" p  : "+p +"\n q  : "+q);

        //generate public key(n,e), private key (d) using prime p and q
        BigInteger[] keyArray = q3.keyScheduling(p,q);  //[0] = n, [1] = e, [2]= d      ,public key(n,e), private key(d)
        BigInteger publicN = keyArray[0];
        BigInteger publicE = keyArray[1];
        BigInteger privateD = keyArray[2];

        FileReader in = null;
        FileWriter out = null;
        FileWriter outHex = null;
        try //(RSA)Encrypt RSA-test.txt and write ciphertext to q3_output_encrypt.txt
        {
            out = new FileWriter("q3_output_encrypt.txt");  //write in decimal value to q3_output_encrypt.txt
            outHex = new FileWriter("q3_output_encrypt_HEX.txt");   //write in hex value to q3_output_encrypt_HEX.txt
            in = new FileReader("RSA-test.txt");    //read RSA-test.txt

            int c = 0;
            String stringC = ""; //used for padding
            String concatString = "";   //used for concatenating the ascii values of characters with (m<n) in mind, where m is plaintext and n is (prime p* prime q).

            System.out.println("\nm<n (m= plaintext, in ascii value),(n= public key, n)\n n:"+publicN);
            System.out.println(" m:");

            while ((c = in.read()) != -1)   //read RSA-text.txt character by character
            {
                stringC = String.valueOf(c);    //c is the ascii value of character
                while (stringC.toCharArray().length < 3)    //padding for ascii value for example: A has 65, becomes 065, while e has 101, remains the same, for consistency purposes
                {
                    stringC = "0" + stringC;
                }
                BigInteger StringAddConcatString = new BigInteger(concatString+ stringC);    //acts as temp, current (String)C concatenate with concatenated String to bigInteger
                if(StringAddConcatString.compareTo(publicN) == -1)          //check if n value of public key is more than concatenated string,if its true then concatenate the strings
                {//publicN can be substituted with BigInteger.valueOf(127) to test encrypt char by char
                    concatString = concatString + stringC;
                }
                else    //if it cannot concatenate anymore, encrypt the concatenated string and empties concatString and add the current String to it.
                {
                    System.out.println("   "+concatString);
                    BigInteger bigConcatString = new BigInteger(concatString);                      //turn concatenated String to bigInteger
                    BigInteger encryptConcat = q3.encryption(publicE,bigConcatString,publicN);      //encrypt the concatenated string
                    String encryptedConcatString = encryptConcat.toString();    //ciphertext in decimal values (base 10)
                    String encryptedConcatStringHex = encryptConcat.toString(16);   //ciphertext in hex values (base 16)
                    out.write(encryptedConcatString+"\n");  //write in decimal value
                    outHex.write( encryptedConcatStringHex.toUpperCase()+"\n"); //write in hex value

                    concatString ="";   //reset concatenated string
                    concatString = concatString+ stringC;   //add the current string to empty string
                }
            }
            if(concatString!= null)     // encrypt remaining plaintext
            {
                System.out.println("   "+concatString);
                BigInteger bigConcatString = new BigInteger(concatString);                      //turn concatenated String to bigInteger
                BigInteger encryptConcat = q3.encryption(publicE,bigConcatString,publicN);      //encrypt the concatenated string
                String encryptedConcatString = encryptConcat.toString();    //ciphertext in decimal values (base 10)
                String encryptedConcatStringHex = encryptConcat.toString(16);    //ciphertext in hex values (base 16)
                out.write(encryptedConcatString+"\n");
                outHex.write(encryptedConcatStringHex.toUpperCase()+"\n");
            }
        }
        finally
        {
            if (in != null)
            {
                in.close();
            }
            if (out != null)
            {
                out.close();
            }
            if (outHex != null)
            {
                outHex.close();
            }
        }

        BufferedReader br = null;
        try //(decrypt ciphertext back to plaintext(in ascii values) to q3_output_decrypt.txt)
        {
            in = new FileReader("q3_output_encrypt.txt");
            br = new BufferedReader(in);
            out = new FileWriter("q3_output_decrypt.txt");
            BigInteger bigLineChars;
            String line;
            while((line=br.readLine())!= null)  //reads line by line
            {
                bigLineChars = new BigInteger(line);
                BigInteger decryptedConcat = q3.decryption(privateD,bigLineChars,publicN);  //decrypt the ciphertext
                String decryptedConcatString = decryptedConcat.toString();
                if (decryptedConcatString.toCharArray().length %3 != 0)
                {   //padding to the left most bit with 0 when (length of total decimal) modulo 3 not equals to 0. Ascii has 3 digits number. The left most bit will not show '0' for int, Biginteger. Thus padding is needed for easier conversion to plaintext characters.
                    decryptedConcatString = "0"+decryptedConcatString;
                }
                out.write(decryptedConcatString+"\n");
            }
        }
        finally
        {
            if(in != null)
            {
                in.close();
            }
            if(out != null)
            {
                out.close();
            }
            if(br!= null)
            {
                br.close();
            }
        }

        try //(convert plaintext(ascii values) to plaintext characters)
        {
            in = new FileReader("q3_output_decrypt.txt");
            out = new FileWriter("q3_output_decrypt_PLAINTEXT.txt");
            br = new BufferedReader(in);
            String stringAscii="";

            int counter=0;
            int asciiCounter=0;
            String line;
            while((line= br.readLine()) != null)    //read line by line
            {
                while(counter<line.toCharArray().length)    //for every 3 numbers, convert it to plaintext character, for example 097 -> 'a', until end of line
                {
                    stringAscii = stringAscii + line.toCharArray()[counter];
                    counter++;
                    asciiCounter++;
                    if (asciiCounter == 3)
                    {
                        asciiCounter = 0;
                        out.write((char) Integer.parseInt(stringAscii));
                        stringAscii = "";
                    }
                }
                counter =0;
            }

        }
        finally
        {
            if(in != null)
            {
                in.close();
            }
            if(out != null)
            {
                out.close();
            }
            if(br != null)
            {
                br.close();
            }
        }

        System.out.println("Encrypted text will be output to file (q3_output_encrypt.txt)" +
                "\nThe ciphertext in hexadecimal is in file (q3_output_encrypt_HEX.txt) " +
                "\nDecrypted text (ascii value) is output to file (q3_output_decrypt.txt)" +
                "\nThe fully recovered plaintext (characters) is in file (q3_output_decrypt_PLAINTEXT.txt)");

    }
}
