using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace CA
{
    public class CesarEncrytpion : Encryption
    {

        /// <summary>
        /// Default constructor
        /// </summary>
        public CesarEncrytpion()
        {

        }
        /// <summary>
        /// Constructor with parameters
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="encryptedText"></param>
        /// <param name="encryptionKey"></param>
        public CesarEncrytpion(string? plainText, string? encryptedText, string encryptionKey)
        {
            this.plainText = plainText;
            this.encryptedText = encryptedText;
            this.encrytpionKey = encryptionKey;
        }
        /// <summary>
        /// 
        /// </summary>
        public void ExtractKey()
        {
            string inputKeys = encrytpionKey;
            string cesarKey = inputKeys[0].ToString();

            convertedEncrpytionKey = Int32.Parse(cesarKey);
        }

        #region Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ASCIIchar"></param>
        /// <returns></returns>
        public byte Decrypt(byte ASCIIchar)
        {
            byte decryptedASCII = ASCIIchar;
            int moduloResults;
            int alphLength = MethodHelpers.alphLower.Length;

            char input = Convert.ToChar(ASCIIchar);

            if (Char.IsUpper(input))
            {
                for (int i = 0; i < MethodHelpers.alphUpper.Length; i++)
                {
                    if (input == MethodHelpers.alphUpper[i])
                    {
                        if ((i - convertedEncrpytionKey) < alphLength)
                        {
                            moduloResults = negativeModulo((i - convertedEncrpytionKey),alphLength);
                            return decryptedASCII = Convert.ToByte(MethodHelpers.alphUpper[moduloResults]);
                        }
                        else
                        {
                            return decryptedASCII = Convert.ToByte(MethodHelpers.alphUpper[i-convertedEncrpytionKey]);
                        }
                    }
                }
            }
            else
            {
                for (int i = 0; i < MethodHelpers.alphLower.Length; i++)
                {
                    if (input == MethodHelpers.alphLower[i])
                    {
                        if ((i - convertedEncrpytionKey) < 0)
                        {

                            moduloResults = negativeModulo((i - convertedEncrpytionKey), alphLength);
                            return decryptedASCII = Convert.ToByte(MethodHelpers.alphLower[moduloResults]);
                        }
                        else
                        {
                            return decryptedASCII = Convert.ToByte(MethodHelpers.alphLower[i-convertedEncrpytionKey]);
                        }
                    }
                }
            }
            return decryptedASCII;
        }
        /// <summary>
        /// 
        /// </summary>
        public void DecryptionStart()
        {
            if (KeyValidation() == false)
            {
                return;
            }

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
        /// 
        /// </summary>
        /// <param name="ASCIIchar"></param>
        /// <returns></returns>
        public byte Encrypt(byte ASCIIchar)
        {
            byte encryptedASCII = ASCIIchar;
            int moduloResults;
            int alphLength = MethodHelpers.alphLower.Length;

            char input = Convert.ToChar(ASCIIchar);

            if(Char.IsUpper(input))
            {
                for(int i = 0; i < MethodHelpers.alphUpper.Length; i++)
                {
                    if(input == MethodHelpers.alphUpper[i])
                    {

                        if((i+ convertedEncrpytionKey) >= alphLength)
                        {
                            moduloResults = (i + convertedEncrpytionKey) % alphLength;
                            return encryptedASCII = Convert.ToByte(MethodHelpers.alphUpper[moduloResults]);
                        }
                        else
                        {
                            return encryptedASCII = Convert.ToByte(MethodHelpers.alphUpper[i + convertedEncrpytionKey]);
                        }
                    }
                }
            }
            else
            {
                for(int i = 0; i < MethodHelpers.alphLower.Length; i++)
                {
                    if (input == MethodHelpers.alphLower[i])
                    {

                        if ((i + convertedEncrpytionKey) >= alphLength)
                        {
                            moduloResults = (i + convertedEncrpytionKey) % alphLength;
                            return encryptedASCII = Convert.ToByte(MethodHelpers.alphLower[moduloResults]);
                        }
                        else
                        {
                            return encryptedASCII = Convert.ToByte(MethodHelpers.alphLower[i + convertedEncrpytionKey]);
                        }
                    }
                }
            }
            return encryptedASCII;
        }

        /// <summary>
        /// 
        /// </summary>
        public void EncryptionStart()
        {
            if (KeyValidation() == false)
            {
                return;
            }

            byte[] codedASCII = MethodHelpers.ascii.GetBytes(plainText);
            byte[] outputASCII = new byte[codedASCII.Length];

            for(int i = 0; i < codedASCII.Length; i++)
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

            encyrptedOutputText = MethodHelpers.ascii.GetString(outputASCII).TrimEnd();

            try
            {
                encryptedText = encyrptedOutputText;
                MethodHelpers.OutputFile(encyrptedOutputText, "crypto.txt");
                Console.WriteLine("Text has been encrypted properly");
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public bool KeyValidation()
        {
            ExtractKey();
            if (convertedEncrpytionKey >= 0 && convertedEncrpytionKey <= 25)
            {
                return true;
            }
            else
            {
                Console.WriteLine("Wrong format of key");
                return false;
            }
        }

        public int negativeModulo(int x, int y)
        {
            return (x % y + y) % y;
        }

        /// <summary>
        /// 
        /// </summary>
        public void KnownPlainTextAttack(string knownText)
        {
            string cipherKnownText = knownText;
            string encryptedCipherText = encryptedText;
            convertedEncrpytionKey = 0;
            byte[] codedASCII = MethodHelpers.ascii.GetBytes(encryptedText);

            while(true)
            {
                byte[] outputASCII = new byte[codedASCII.Length];

                for (int j = 0; j < codedASCII.Length; j++)
                {
                    if (MethodHelpers.checkIfLetter(codedASCII[j]) == true)
                    {
                        outputASCII[j] = Decrypt(codedASCII[j]);
                    }
                    else
                    {
                        outputASCII[j] = codedASCII[j];
                    }
                }
                encryptedCipherText = MethodHelpers.ascii.GetString(outputASCII).TrimEnd();
                if(encryptedCipherText.Contains(cipherKnownText))
                {
                    DecryptionStart();
                    break;
                }
                convertedEncrpytionKey++;
                if (convertedEncrpytionKey > 26)
                {
                    Console.WriteLine("Wrong cipher key");
                    break;
                }

            }
            MethodHelpers.OutputFile(convertedEncrpytionKey.ToString(), "key-new.txt");
        }

        /// <summary>
        /// 
        /// </summary>
        public void UnknownPlanTextAttack()
        {
            convertedEncrpytionKey = 1;
            byte[] codedASCII = MethodHelpers.ascii.GetBytes(encryptedText);
            string[] decryptedTextArray = new string[25];
            for(int i = 1; i < 26; i++)
            {
                byte[] outputASCII = new byte[codedASCII.Length];

                for (int j = 0; j < codedASCII.Length; j++)
                {
                    if (MethodHelpers.checkIfLetter(codedASCII[j]) == true)
                    {
                        outputASCII[j] = Decrypt(codedASCII[j]);
                    }
                    else
                    {
                        outputASCII[j] = codedASCII[j];
                    }
                }
                decryptedTextArray[i-1] = MethodHelpers.ascii.GetString(outputASCII);
                convertedEncrpytionKey++;
            }

           MethodHelpers.OutputFileArray(decryptedTextArray, "plain.txt");
            
        }

        #endregion

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
        public int convertedEncrpytionKey = 0;

        #endregion
    }
}
