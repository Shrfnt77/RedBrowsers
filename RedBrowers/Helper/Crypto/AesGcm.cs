using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RedBrowers
{

    //https://raw.githubusercontent.com/dvsekhvalnov/jose-jwt/master/jose-jwt/native/BCrypt.cs
    public static class AesGcm
    {
        /// <summary>
        /// Performs AES encryption in GCM chaining mode over plain text
        /// </summary>
        /// <param name="key">aes key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aad">additional authn data</param>
        /// <param name="plainText">plain text message to be encrypted</param>
        /// <returns>2 byte[] arrays: [0]=cipher text, [1]=authentication tag</returns>
        /// /// <exception cref="CryptographicException">if encryption failed by any reason</exception>
        public static byte[][] Encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plainText)
        {
            IntPtr hAlg = OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
            IntPtr hKey, keyDataBuffer = ImportKey(hAlg, key, out hKey);

            byte[] cipher;
            byte[] tag = new byte[MaxAuthTagSize(hAlg)];

            var authInfo = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, tag);
            using (authInfo)
            {
                byte[] ivData = new byte[tag.Length];

                int cipherSize = 0;

                uint status = BCrypt.BCryptEncrypt(hKey, plainText, plainText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref cipherSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() (get size) failed with status code:{0}", status));

                cipher = new byte[cipherSize];

                status = BCrypt.BCryptEncrypt(hKey, plainText, plainText.Length, ref authInfo, ivData, ivData.Length,
                                              cipher, cipher.Length, ref cipherSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() failed with status code:{0}", status));

                Marshal.Copy(authInfo.pbTag, tag, 0, authInfo.cbTag);
            }

            BCrypt.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            BCrypt.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return new[] { cipher, tag };
        }

        /// <summary>
        /// Performs AES decryption in GCM chaning mode over cipher text
        /// </summary>
        /// <param name="key">aes key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aad">additional authn data</param>
        /// <param name="plainText">plain text message to be encrypted</param>
        /// <returns>decrypted plain text messages</returns>
        /// <exception cref="CryptographicException">if decryption failed by any reason</exception>
        public static byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
            IntPtr hAlg = OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
            IntPtr hKey, keyDataBuffer = ImportKey(hAlg, key, out hKey);

            byte[] plainText;

            var authInfo = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
            using (authInfo)
            {
                byte[] ivData = new byte[MaxAuthTagSize(hAlg)];

                int plainTextSize = 0;

                uint status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref plainTextSize, 0x0);

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() (get size) failed with status code: {0}", status));

                plainText = new byte[plainTextSize];

                status = BCrypt.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, plainText, plainText.Length, ref plainTextSize, 0x0);

                if (status == BCrypt.STATUS_AUTH_TAG_MISMATCH)
                    throw new CryptographicException("BCrypt.BCryptDecrypt(): authentication tag mismatch");

                if (status != BCrypt.ERROR_SUCCESS)
                    throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() failed with status code:{0}", status));
            }

            BCrypt.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            BCrypt.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return plainText;
        }

        private static int MaxAuthTagSize(IntPtr hAlg)
        {
            byte[] tagLengthsValue = GetProperty(hAlg, BCrypt.BCRYPT_AUTH_TAG_LENGTH);

            return BitConverter.ToInt32(new[] { tagLengthsValue[4], tagLengthsValue[5], tagLengthsValue[6], tagLengthsValue[7] }, 0);
        }

        private static IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
        {
            IntPtr hAlg = IntPtr.Zero;

            uint status = BCrypt.BCryptOpenAlgorithmProvider(out hAlg, alg, provider, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}", status));

            byte[] chainMode = Encoding.Unicode.GetBytes(chainingMode);
            status = BCrypt.BCryptSetAlgorithmProperty(hAlg, BCrypt.BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}", status));

            return hAlg;
        }
        public static byte[] Concat(params byte[][] arrays)
        {
            byte[] result = new byte[arrays.Sum(a => (a?.Length ?? 0))];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null) continue;

                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }
        private static IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
        {
            byte[] objLength = GetProperty(hAlg, BCrypt.BCRYPT_OBJECT_LENGTH);

            int keyDataSize = BitConverter.ToInt32(objLength, 0);

            IntPtr keyDataBuffer = Marshal.AllocHGlobal(keyDataSize);

            byte[] keyBlob = Concat(BCrypt.BCRYPT_KEY_DATA_BLOB_MAGIC, BitConverter.GetBytes(0x1), BitConverter.GetBytes(key.Length), key);

            uint status = BCrypt.BCryptImportKey(hAlg, IntPtr.Zero, BCrypt.BCRYPT_KEY_DATA_BLOB, out hKey, keyDataBuffer, keyDataSize, keyBlob, keyBlob.Length, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptImportKey() failed with status code:{0}", status));

            return keyDataBuffer;
        }

        private static byte[] GetProperty(IntPtr hAlg, string name)
        {
            int size = 0;

            uint status = BCrypt.BCryptGetProperty(hAlg, name, null, 0, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() (get size) failed with status code:{0}", status));

            byte[] value = new byte[size];

            status = BCrypt.BCryptGetProperty(hAlg, name, value, value.Length, ref size, 0x0);

            if (status != BCrypt.ERROR_SUCCESS)
                throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() failed with status code:{0}", status));

            return value;
        }
    }
    public static class BCrypt
    {
        public const uint ERROR_SUCCESS = 0x00000000;
        public const uint BCRYPT_PAD_PSS = 8;
        public const uint BCRYPT_PAD_OAEP = 4;

        public static readonly byte[] BCRYPT_KEY_DATA_BLOB_MAGIC = BitConverter.GetBytes(0x4d42444b);

        public const string BCRYPT_OBJECT_LENGTH = "ObjectLength";
        public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public const string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
        public const string BCRYPT_CHAINING_MODE = "ChainingMode";
        public const string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
        public const string BCRYPT_AES_ALGORITHM = "AES";

        public const string MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider";

        public const int BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x00000001;
        public const int BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 0x00000001;

        public const uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_PSS_PADDING_INFO
        {
            public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
            {
                this.pszAlgId = pszAlgId;
                this.cbSalt = cbSalt;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public int cbSalt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag) : this()
            {
                dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;
                cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

                if (iv != null)
                {
                    cbNonce = iv.Length;
                    pbNonce = Marshal.AllocHGlobal(cbNonce);
                    Marshal.Copy(iv, 0, pbNonce, cbNonce);
                }

                if (aad != null)
                {
                    cbAuthData = aad.Length;
                    pbAuthData = Marshal.AllocHGlobal(cbAuthData);
                    Marshal.Copy(aad, 0, pbAuthData, cbAuthData);
                }

                if (tag != null)
                {
                    cbTag = tag.Length;
                    pbTag = Marshal.AllocHGlobal(cbTag);
                    Marshal.Copy(tag, 0, pbTag, cbTag);

                    cbMacContext = tag.Length;
                    pbMacContext = Marshal.AllocHGlobal(cbMacContext);
                }
            }

            public void Dispose()
            {
                if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
                if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
                if (pbAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pbAuthData);
                if (pbMacContext != IntPtr.Zero) Marshal.FreeHGlobal(pbMacContext);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_KEY_LENGTHS_STRUCT
        {
            public int dwMinLength;
            public int dwMaxLength;
            public int dwIncrement;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_OAEP_PADDING_INFO
        {
            public BCRYPT_OAEP_PADDING_INFO(string alg)
            {
                pszAlgId = alg;
                pbLabel = IntPtr.Zero;
                cbLabel = 0;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public IntPtr pbLabel;
            public int cbLabel;
        }

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                              [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                              uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty")]
        public static extern uint BCryptGetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptSetProperty")]
        internal static extern uint BCryptSetAlgorithmProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptImportKey(IntPtr hAlgorithm,
                                                  IntPtr hImportKey,
                                                  [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                  out IntPtr phKey,
                                                  IntPtr pbKeyObject,
                                                  int cbKeyObject,
                                                  byte[] pbInput, //blob of type BCRYPT_KEY_DATA_BLOB + raw key data = (dwMagic (4 bytes) | uint dwVersion (4 bytes) | cbKeyData (4 bytes) | data)
                                                  int cbInput,
                                                  uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptEncrypt(IntPtr hKey,
                                                byte[] pbInput,
                                                int cbInput,
                                                ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                byte[] pbIV, int cbIV,
                                                byte[] pbOutput,
                                                int cbOutput,
                                                ref int pcbResult,
                                                uint dwFlags);

        [DllImport("bcrypt.dll")]
        internal static extern uint BCryptDecrypt(IntPtr hKey,
                                                  byte[] pbInput,
                                                  int cbInput,
                                                  ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                  byte[] pbIV,
                                                  int cbIV,
                                                  byte[] pbOutput,
                                                  int cbOutput,
                                                  ref int pcbResult,
                                                  int dwFlags);
    }
}
