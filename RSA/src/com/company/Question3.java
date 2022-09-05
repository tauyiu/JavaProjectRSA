//reference list: lecture slides, tutorials, textbooks, stack overflow
package com.company;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Question3
{
    public BigInteger[] keyScheduling(BigInteger P, BigInteger Q)
    {
        SecureRandom rand = new SecureRandom(); //an even more secure rng than Random rng
        BigInteger n = P.multiply(Q);   //n = p*q
        BigInteger one = BigInteger.valueOf(1); //1
        BigInteger pMinusOne = P.subtract(one); //p-1
        BigInteger qMinusOne = Q.subtract(one); //q-1
        BigInteger phi = pMinusOne.multiply(qMinusOne); //(p-1)*(q-1)
        System.out.println("Phi : "+phi);
        System.out.println(" n  : "+n);

        BigInteger e; //public exponent e
        do e = new BigInteger(phi.bitLength(), rand);  //randomly generate e, until gcd (e, phi) = 1
        while(e.compareTo(BigInteger.ONE)<=0 || e.compareTo(phi) >=0 || !gcd(e,phi).equals(BigInteger.ONE));       //e {1,2,.. phi(n)-1}
        System.out.println(" e  : "+ e);

        BigInteger d = extendedEuclid(e,phi);
        System.out.println(" d  : "+ d); //d = e^-1 (mod phi(n))

        BigInteger array[] = new BigInteger[3]; //return 3 values, public key(n,e), private key(d)
        array[0] = n;
        array[1] = e;
        array[2] = d;
        return array;
    }

    public static BigInteger gcd(BigInteger a, BigInteger b)
    {
        if (a==BigInteger.ZERO) //if a == 0
        {
            return b;
        }
        return gcd(b.mod(a),a); //recursion b%a,a
    }

    public BigInteger extendedEuclid(BigInteger a, BigInteger n) //show inverse modulo,
    {
        //referenced from geeksforgeeks modular multiplicative inverse
        //ax +by = gcd(a,b) ,where b is n,
        //ax +ny = gcd(a,n)
        //since gcd = 1, for gcd(e,phi),
        //ax + ny = 1
        //if taken modulo n from both side, ax +ny = 1(modn)
        //ny(mod n) would always be 0 for integer y,then it is removed, ax = 1(mod n), and x is multiplicative inverse of a.
        BigInteger y = BigInteger.ZERO;
        BigInteger x = BigInteger.ONE;
        BigInteger n0 = n;
        if(n.compareTo(BigInteger.ONE) == 0)    //n == 1
        {
            return BigInteger.ZERO;
        }
        while(a.compareTo(BigInteger.ONE) == 1) //a > 1
        {
            BigInteger q = a.divide(n);
            BigInteger t = n;
            n = a.mod(n);
            a = t;
            t = y;
            y = x.subtract((q).multiply(y));
            x = t;
        }
        if (x.compareTo(BigInteger.ZERO)==-1)   //x<0, x+original n,so no negative value for x
        {
            x = x.add(n0);
        }
        return x;
    }

    public BigInteger numberGenerator(int numInput)    //generate a number more than 2^64 and up to numInput bits
    {
        BigInteger constantNum = BigInteger.TWO;    // constantNum = 2
        constantNum = constantNum.pow(64).add(BigInteger.ONE);  // (2^(64)) +1 , larger than 2^64

        BigInteger random = new BigInteger(numInput,new SecureRandom());    //generate a random number up to the bits length of 77
        BigInteger total = constantNum.add(random);   //add together both number, so that generated number is at least 2^64

        return total;
    }

    public boolean primeTest(BigInteger n) //lehmann algorithm, reference from lab 5
    {
        boolean boolCheck;
        int i = 10; //the higher value, the better. For higher probability that the number is a prime via checking. Example 10 times (true) has 0.999 probability it being a prime.
        int iTimes = i;
        int tTimes= i;
        SecureRandom rand = new SecureRandom();

        do
        { //repeat i times
            BigInteger randomA= new BigInteger(n.bitLength(),rand);    //generate random number a, with the same bits as n
            while(randomA.compareTo(n) ==0 || randomA.compareTo(n)== 1)         // (randomA < n ) or generate new random number for a
            {   //randomA == n OR randomA > n then
                randomA= new BigInteger(n.bitLength(),rand);
            }
            BigInteger resultR = binaryModularExponent((n.subtract(BigInteger.ONE)).divide(BigInteger.TWO),randomA,n);
            //r = a^((p-1)/2) mod n, calculate using fast binary modular exponent

            if (resultR.compareTo(BigInteger.ONE) == 0 || resultR.compareTo((n.subtract(BigInteger.ONE))) == 0)
            {   //check if r is 1 OR r = n-1
                iTimes--;
                boolCheck = true;
            }
            else
            {   //if does not satisfy the condition above, n is definitely not a prime, (if r != 1 OR p-1)
                return false;
            }
            i--;
        }while(i>0);

        if(iTimes== i)  //if r equals
        {
            System.out.println("Passes "+tTimes+" times\n"+n+"\nis prime, with the probability of "+ (1-(1/(Math.pow(2,tTimes))))+"\n");
        }
        return boolCheck;
    }

    public BigInteger encryption(BigInteger e,BigInteger plainText, BigInteger n)
    {
        return binaryModularExponent(e,plainText,n);    //ciphertext = (plaintext^(public key e)) mod (public key n),which can be calculated using fast binary modular exponent(exponent,base,mod)
    }

    public BigInteger decryption(BigInteger d,BigInteger cipherText,BigInteger n)
    {
        return binaryModularExponent(d,cipherText,n); //plaintext = (ciphertext^(private key d)) mod (public key n), which can be calculated using fast binary modular exponent(exponent, base, mod)
    }

    public BigInteger binaryModularExponent(BigInteger exponentH,BigInteger baseX,BigInteger modN)  //referred to lab 6
    {
        if(modN.compareTo(BigInteger.ONE) ==0) //mod n ==1
        {
            return BigInteger.ZERO;
        }
        BigInteger result = BigInteger.ONE;
        baseX = baseX.mod(modN);

        while (exponentH.compareTo(BigInteger.ZERO) == 1)   //h>0
        {
            if(exponentH.mod(BigInteger.TWO).compareTo(BigInteger.ONE) ==0) //h mod 2 == 1
            {
                result = (result.multiply(baseX)).mod(modN);
            }
            exponentH = exponentH.shiftRight(1);    //shift exponent by 1 bit to the right
            baseX = (baseX.multiply(baseX)).mod(modN);
        }
        return result;
    }

    public int getInput()   //get input for number of bits length of primes for RSA
    {
        Scanner sc = new Scanner(System.in);
        int userNumInput = 0;
        boolean inputCheck = false;
        System.out.println("User input must be in the range of 65 to 1024");
        while(inputCheck == false)
        {
            try
            {
                userNumInput = sc.nextInt();
                inputCheck = true;
                if(userNumInput < 65)
                {
                    System.out.println("User input must be in the range of 65 to 1024");
                    inputCheck= false;
                }
                else if(userNumInput >2048)
                {
                    System.out.println("User input must be in the range of 65 to 1024");
                    inputCheck= false;
                }
            }
            catch (InputMismatchException e)
            {
                System.out.println("Input numbers only!");
                sc.nextLine();
            }
        }
        return userNumInput;
    }
}
