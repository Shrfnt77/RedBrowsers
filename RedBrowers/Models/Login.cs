using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedBrowers
{
    internal class Login
    {
        public Login(string url,string username , string password , string browser) 
        {
            Url= url;
            Username= username;
            Password= password;
            Browser= browser;

        }

        public override string ToString()
        {
            return $"-------------------\nUrl : {Url} \nUsername : {Username} \nPassword : {Password} \nBrowser : {Browser}\n---------------";
        }
        public string Browser { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Url { get; set; }
    }
}
