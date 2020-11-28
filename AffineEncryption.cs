using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Text;


namespace CA
{
    public class AffineEncryption : Encryption
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AffineEncryption() { }

        /// <summary>
        /// Constructor with parameters
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="encryptedText"></param>
        /// <param name="encryptionKey"></param>
        public AffineEncryption(string? plainText, string? encryptedText, string encryptionKey)
        {
            this.plainText = plainText;
            this.encryptedText = encryptedText;
            this.encrytpionKey = encryptionKey;
            
        }

        #region utility methods for affine encryption

        /// <summary>
        /// Utility method for calc negative modulo
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns>int</returns>
        public int negativeModulo(int x, int y)
        {
            return (x % y + y) % y;
        }

        /// <summary>
        /// Utility method for calculation - encryption
        /// </summary>
        /// <param name="alphIndex"></param>
        /// <returns>int</returns>
        public int CalculationForEncryption(int alphIndex)
        {
            int i = (bagOfKeys[0] * alphIndex + bagOfKeys[1]) % MethodHelpers.alphLower.Length;

            return i;
        }

        /// <summary>
        /// Utility method for calculation - decryption
        /// </summary>
        /// <param name="alphIndex"></param>
        /// <returns>int</returns>
        public void CalculationForDecryption()
        {
            int index = 0;

            while ((bagOfKeys[0] * index)%MethodHelpers.alphLower.Length != 1)
            {
                index++;
            }
            decodingKey = index;
            
        }
        /// <summary>
        /// Utility method for affine key breaker
        /// </summary>
        /// <param name="alphIndex"></param>
        /// <returns>int</returns>
        public int CalculationForDecryption(int key)
        {
            int index = 0;

            while ((key * index) % MethodHelpers.alphLower.Length != 1)
            {
                index++;
            }
            return index;

        }

        /// <summary>
        /// Decoding chars
        /// </summary>
        /// <param name="charIndex"></param>
        /// <returns>int</returns>
        public int Decode(int charIndex)
        {
            if (charIndex - bagOfKeys[1] < 0)
            {
                return negativeModulo((decodingKey * (charIndex - bagOfKeys[1])), 26);
            }
            else
            {
                return decodingKey * (charIndex - bagOfKeys[1]) % 26;
            }
        }
        /// <summary>
        /// Decoding chars
        /// </summary>
        /// <param name="charIndex"></param>
        /// <returns>int</returns>
        public int Decode(int charIndex, int keyA, int keyB)
        {
            if (charIndex - keyB < 0)
            {
                return negativeModulo((keyA * (charIndex - keyB)), 26);
            }
            else
            {
                return keyA * (charIndex - keyB) % 26;
            }
        }
        #endregion

        /// <summary>
        /// Decryption 
        /// </summary>
        /// <param name="ASCIIchar"></param>
        /// <returns>byte</returns>
        public byte Decrypt(byte ASCIIchar)
        {
            byte decryptedASCII = ASCIIchar;
            int alphLength = MethodHelpers.alphLower.Length;

            char input = Convert.ToChar(ASCIIchar);

            if (Char.IsUpper(input))
            {
                for (int i = 0; i < MethodHelpers.alphUpper.Length; i++)
                {
                    if (input == MethodHelpers.alphUpper[i])
                    {
                        int decodedChar = Decode(i);
                        return Convert.ToByte(MethodHelpers.alphUpper[decodedChar]);

                    }
                }
            }
            else
            {
                for (int i = 0; i < MethodHelpers.alphLower.Length; i++)
                {
                    if (input == MethodHelpers.alphLower[i])
                    {
                        int decodedChar = Decode(i);
                        return Convert.ToByte(MethodHelpers.alphLower[decodedChar]);
                    }
                }
            }
            return decryptedASCII;
        }

        /// <summary>
        /// Run decryption algorithm
        /// </summary>
        public void DecryptionStart()
        {
            if(KeyValidation() == false)
            {
                return;
            }
            CalculationForDecryption();
            extractKeys();

            byte[] codedASCII = MethodHelpers.ascii.GetBytes(encryptedText);
            byte[] outputASCII = new byte[codedASCII.Length];


            for (int i = 0; i < codedASCII.Length; i++)
            {
                if (MethodHelpers.checkIfLetter(codedASCII[i]) == true)
                {
                    outputASCII[i] = Decrypt(codedASCII[i]);
                }
                else
                {
                    outputASCII[i] = codedASCII[i];
                }
            }

            decryptedOutputText = MethodHelpers.ascii.GetString(outputASCII);

            try
            {
                Console.WriteLine(decryptedOutputText);
                MethodHelpers.OutputFile(decryptedOutputText, "decrypt.txt");
                Console.WriteLine("Text has been decrypted properly");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
       
        /// <summary>
        /// Return encrypted char
        /// </summary>
        /// <param name="ASCIIchar"></param>
        /// <returns>byte</returns>
        public byte Encrypt(byte ASCIIchar)
        {
            byte encryptedASCII = ASCIIchar;
            int alphLength = MethodHelpers.alphLower.Length;

            char input = Convert.ToChar(ASCIIchar);

            if (Char.IsUpper(input))
            {
                for(int i = 0; i < alphLength; i++)
                {
                    if(input == MethodHelpers.alphUpper[i])
                    {
                        int index = CalculationForEncryption(i);
                        return Convert.ToByte(MethodHelpers.alphUpper[index]);
                    }
                }
            }
            else
            {
                for(int i = 0; i < alphLength; i++)
                {
                    if (input == MethodHelpers.alphLower[i])
                    {
                        int index = CalculationForEncryption(i);
                        return Convert.ToByte(MethodHelpers.alphLower[index]);
                    }
                }
            }

            return ASCIIchar;
        }

        /// <summary>
        /// Run encryption algortihm
        /// </summary>
        public void EncryptionStart()
        {
            if (KeyValidation() == false)
            {
                return;
            }

            byte[] codedASCII = MethodHelpers.ascii.GetBytes(plainText);
            byte[] outputASCII = new byte[codedASCII.Length];

            for (int i = 0; i < codedASCII.Length; i++)
            {
                if (MethodHelpers.checkIfLetter(codedASCII[i]) == true)
                {
                    outputASCII[i] = Encrypt(codedASCII[i]);
                }
                else
                {
                    outputASCII[i] = codedASCII[i];
                }
            }

            encyrptedOutputText = MethodHelpers.ascii.GetString(outputASCII);
            try
            {
                encryptedText = encyrptedOutputText;
                MethodHelpers.OutputFile(encyrptedOutputText, "crypto.txt");
                Console.WriteLine("Text has been encrypted properly");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
        /// <summary>
        /// Utility method for exctracting keys
        /// </summary>
        public void extractKeys()
        {

            string[] keys = convertedEncrpytionKey.Split(' ');

            int keyA = Int32.Parse(keys[0]);
            int keyB = Int32.Parse(keys[1]);

            bagOfKeys = new int[] { keyA, keyB };

        }
        /// <summary>
        /// Utility metod for ectracting avaliable affine keys for alph 
        /// </summary>
        public void extractAttackDecryptionKeys()
        {
            listOfAvaliableKeys = new List<int>();
            for (int i = 1; i < 26; i++)
            {
                if (extractNWD(i, 26) == 1)
                {
                    listOfAvaliableKeys.Add(i);
                }
            }
        }

        /// <summary>
        /// Valide Key
        /// </summary>
        /// <returns>bool</returns>
        public bool KeyValidation()
        {
            extractKeys();
            int firstCondition = extractNWD(bagOfKeys[0], bagOfKeys[1]);
            var secondConditon = (bagOfKeys[0] * 1 / bagOfKeys[0])%MethodHelpers.alphLower.Length;
            if(firstCondition == 1 && secondConditon == 1)
            {
                return true;
            }
            else
            {
                Console.WriteLine("Wrong format of key");
                return false;
            }
        }
        /// <summary>
        /// Extract NWD 
        /// </summary>
        /// <param name="firstKey"></param>
        /// <param name="SecondKey"></param>
        /// <returns></returns>
        public int extractNWD(int firstKey, int SecondKey)
        {
            int NWD;
            while (firstKey != SecondKey)
            {
                if (firstKey > SecondKey)
                    firstKey -= SecondKey;
                else
                    SecondKey -= firstKey;
            }
            return NWD = firstKey;
        }
        /// <summary>
        /// Initiate funcion for known plain text attack
        /// </summary>
        /// <param name="knownText"></param>
        public void KnownPlainTextAttack(string knownText)
        {
            string cipherKnownText = knownText;
            string encryptedCipherText = encryptedText;
            extractAttackDecryptionKeys();
            byte[] codedASCII = MethodHelpers.ascii.GetBytes(encryptedText);
            int keyIndex = 0;
            int keyb = 0;
            int outputIndex = 0;
            int decodingKey = 0;
            
            while (true)
            {
                try
                {
                    byte[] outputASCII = new byte[codedASCII.Length];
                    for (int j = 0; j < codedASCII.Length; j++)
                    {
                        if (MethodHelpers.checkIfLetter(codedASCII[j]) == true)
                        {
                            outputASCII[j] = NonPlaintTextAttackDecoder(codedASCII[j], listOfAvaliableKeys[keyIndex], keyb);
                        }
                        else
                        {
                            outputASCII[j] = codedASCII[j];
                        }
                    }
                    
                    encryptedCipherText = MethodHelpers.ascii.GetString(outputASCII);

                    if (encryptedCipherText.Contains(cipherKnownText))
                    {
                        decodingKey = CalculationForDecryption(listOfAvaliableKeys[keyIndex]);
                        break;
                    }
                    outputIndex++;
                    keyb++;
                    if (keyb > 25)
                    {
                        keyb = 0;
                        keyIndex++;
                    }
                   
                }
                catch(ArgumentOutOfRangeException)
                {
                    Console.WriteLine("INVALID KEY");
                    break;
                }
            }

            string outputKey = decodingKey.ToString() + " " + keyb.ToString();
            Console.WriteLine(outputKey);
            DecryptionStart();
            MethodHelpers.OutputFile(outputKey, "key-new.txt");
        }

        /// <summary>
        /// Unknow Plain Text Attack part of decoding funcion
        /// </summary>
        /// <param name="ASCIIchar"></param>
        /// <param name="i"></param>
        /// <param name="j"></param>
        /// <returns>byte</returns>
        public byte NonPlaintTextAttackDecoder(byte ASCIIchar, int i, int j)
        {
            int alphLength = MethodHelpers.alphLower.Length;

            char input = Convert.ToChar(ASCIIchar);

            if (Char.IsUpper(input))
            {
                for (int k = 0; k < MethodHelpers.alphUpper.Length; k++)
                {
                    if (input == MethodHelpers.alphUpper[k])
                    {
                        int decodedChar = Decode(k, i, j);
                        return Convert.ToByte(MethodHelpers.alphUpper[decodedChar]);

                    }
                }
            }
            else
            {
                for (int k = 0; k < MethodHelpers.alphLower.Length; k++)
                {
                    if (input == MethodHelpers.alphLower[k])
                    {
                        int decodedChar = Decode(k, i, j);
                        return Convert.ToByte(MethodHelpers.alphLower[decodedChar]);
                    }
                }
            }
            return ASCIIchar;
        }

        /// <summary>
        /// Method for uknown plan text attack
        /// </summary>
        public void UnknownPlanTextAttack()
        {
            extractAttackDecryptionKeys();
            byte[] codedASCII = MethodHelpers.ascii.GetBytes(encryptedText);
            int KeyIndex = 0;
            int keyb = 0;
            int outputIndex = 0;
            string[] decryptedTextArray = new string[312];
            while (listOfAvaliableKeys.Count > KeyIndex)
            {
                byte[] outputASCII = new byte[codedASCII.Length];
                for (int j = 0; j < codedASCII.Length; j++)
                {
                    if (MethodHelpers.checkIfLetter(codedASCII[j]) == true)
                    {
                        outputASCII[j] = NonPlaintTextAttackDecoder(codedASCII[j], listOfAvaliableKeys[KeyIndex], keyb);
                    }
                    else
                    {
                        outputASCII[j] = codedASCII[j];
                    }
                }
                
                decryptedTextArray[outputIndex] = MethodHelpers.ascii.GetString(outputASCII);
                outputIndex++;
                keyb++;
                if (keyb > 25)
                {
                    keyb = 0;
                    KeyIndex++;
                }
            }
            
            MethodHelpers.OutputFileArray(decryptedTextArray, "plain2.txt");
        }

        #region Properties
        /// <summary>
        /// Plain text for encryption
        /// </summary>
        public string? plainText { get; set; }
        /// <summary>
        /// encrypted text for decryption
        /// </summary>
        public string? encryptedText { get; set; }
        /// <summary>
        /// encrpytion key for encrypt/decrypt
        /// </summary>
        public string encrytpionKey { get; set; }
        /// <summary>
        /// output value of encryption result 
        /// </summary>
        public string encyrptedOutputText = "";
        /// <summary>
        /// output value of decryption result
        /// </summary>
        public string decryptedOutputText = "";
        /// <summary>
        /// get key from bunch of keys
        /// </summary>
        public string convertedEncrpytionKey => encrytpionKey;
        /// <summary>
        /// converted keys 
        /// </summary>
        public int[] bagOfKeys;
        /// <summary>
        /// key for decoding affine
        /// </summary>
        public int decodingKey;
        ///// <summary>
        ///// possible K(a,x) a keys for alph 
        ///// </summary>
        List<int> listOfAvaliableKeys;
        #endregion
    }
}
