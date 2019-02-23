unit usnoop;

interface

uses Windows,  Classes, winsock, Pcap;

const
  SNOOP_DEFAULT_SNAPLEN = 1600;
  SNOOP_MAC_SIZE = 6;

type
  TPcap = pcap_t;
  PPcap = ppcap_t;
  PCAP_PKTHDR = Pcap.pcap_pkthdr;
  PPCAP_PKTHDR = ^PCAP_PKTHDR;
  PPPCAP_PKTHDR = ^PPCAP_PKTHDR;

// ----------------------------------------------------------------------------
// Ethernet Header
// ----------------------------------------------------------------------------
const
  PROTO_IP      =	         $0800;
  PROTO_ARP     =	         $0806;
  PROTO_RARP    =	         $8035;
  PROTO_XNS     =	         $0600;
  PROTO_SNMP    =	         $814C;
  PROTO_OLD_IPX =	         $8137;
  PROTO_NOVELL  =	         $8138;
  PROTO_IPNG    =	         $86DD;

type
  SNOOPMACADDRESS = array[0 .. SNOOP_MAC_SIZE - 1] of UCHAR;
  PSNOOPMACADDRESS = ^SNOOPMACADDRESS;
  PPChar = ^PChar;

type
  ETHERNET_HDR = packed record
	Destination:             SNOOPMACADDRESS;
	Source:                  SNOOPMACADDRESS;
	Protocol:                WORD;
  end;
  PETHERNET_HDR = ^ETHERNET_HDR;

// ----------------------------------------------------------------------------
// IP Header
// ----------------------------------------------------------------------------
const
  PROTO_ICMP = 1;
  PROTO_TCP = 6;
  PROTO_UDP = 17;

type
  IP_HDR = packed record
	VerLen:                  UCHAR;
	Service:                 UCHAR;
	Length:                  WORD;
	Ident:                   WORD;
	FlagOff:                 WORD;
	TimeLive:                UCHAR;
	Protocol:                UCHAR;
	Checksum:                WORD;
	Source:                  DWORD;
	Destination:             DWORD;
  end;
  PIP_HDR = ^IP_HDR;
  PPIP_HDR = ^PIP_HDR;

// ----------------------------------------------------------------------------
// ARP Header
// ----------------------------------------------------------------------------
const
  ARP_REQUEST = $0001;
  ARP_REPLY = $0002;
  RARP_REQUEST = $0003;
  RARP_REPLY = $0004;

type
  ARP_HDR = packed record
	HardwareType:            WORD;
	ProtocolType:            WORD;
	HLen:                    UCHAR;
	PLen:                    UCHAR;
	Operation:               WORD;
	SenderHA:                SNOOPMACADDRESS;
	SenderIP:                DWORD;
	TargetHA:                SNOOPMACADDRESS;
	TargetIP:                DWORD;
  end;
  PARP_HDR = ^ARP_HDR;
  PPARP_HDR = ^PARP_HDR;

// ----------------------------------------------------------------------------
// ICMP Header
// ----------------------------------------------------------------------------
type
  ICMP_HDR = packed record
	VerPrio:                 UCHAR;
	FlowLabel:               array[0..2] of UCHAR;
	Length:                  WORD;
	NextHadr:                UCHAR;
	HopLimit:                UCHAR;
	Source:                  array[0..15] of UCHAR;
	Destination:             array[0..15] of UCHAR;
  end;
  PICMP_HDR = ^ICMP_HDR;
  PPICMP_HDR = ^PICMP_HDR;

// ----------------------------------------------------------------------------
// TCP Header
// ----------------------------------------------------------------------------
const
  TCP_FLAG_FIN =	         $01;
  TCP_FLAG_SYN =	         $02;
  TCP_FLAG_RST =	         $04;
  TCP_FLAG_PSH =	         $08;
  TCP_FLAG_ACK =	         $10;
  TCP_FLAG_URG =	         $20;

type
  TCP_HDR = packed record
	Source:                  WORD;
	Destination:             WORD;
	Seq:                     DWORD;
	Ack:                     DWORD;
	Off_Rsvd:                UCHAR;
	Rsvd_Flags:              UCHAR;
	Window:                  WORD;
	Checksum:                WORD;
	UrgPoint:                WORD;
  end;
  PTCP_HDR = ^TCP_HDR;
  PPTCP_HDR = ^PTCP_HDR;

// ----------------------------------------------------------------------------
// UDP Header
// ----------------------------------------------------------------------------
type
  UDP_HDR = packed record
	Source:                  WORD;
	Destination:             WORD;
	Length:                  WORD;
	Checksum:                WORD;
  end;
  PUDP_HDR = ^UDP_HDR;
  PPUDP_HDR = ^PUDP_HDR;

//*******************************************

   TOnGetRemoteAdapterInfo = procedure (
	//Sender: TObject;
	AdapterNames: TStringList;
	AdapterDescriptions: TStringList;
	var AdapterIndex: Integer) of object;

  TOnCaptureEvent = procedure (
	//Sender: TObject;
	PacketHeader: PPCAP_PKTHDR;
	EthernetHeader: PETHERNET_HDR) of object;

type
   TSnoopAdapter = class(Tobject)
   private
     Fname: String;
     FDescription:string;
     FIndex:dword;
   public
     constructor Create(const Adescription,AName: String;Aindex:dword) ;
     property name: String read Fname;
     property Description: String read FDescription;
     property Index: dword read FIndex;
   end;

TCustomSnoop = class;
  TSnoopThread = class(TThread)
  protected
	FSnoop: TCustomSnoop;
  public
	property Snoop: TCustomSnoop read FSnoop write FSnoop;
  public
	constructor Create(Snoop: TCustomSnoop);
	destructor Destroy; override;
	procedure Open;
	procedure Close;
	procedure Execute; override;
  end;

TCustomSnoop = class(Tobject)
  protected
	// property
	FActive: Boolean;
	FAdapterIndex: Integer;
	FAdapterName: String;
	FAdapterDescription: String;
	FAdapterNames: TStringList;
	FAdapterDescriptions: TStringList;
	FThreadSafe: Boolean;
	FFilter: String;
	FSnapLen: Integer;
	FFlags: Integer;
	FReadTimeOut: Integer;
  FVersion:string;
	FError: String;
	FSourceName: String;
	FOnGetRemoteAdapterInfo: TOnGetRemoteAdapterInfo;
	procedure SetAdapterIndex(Value: Integer);
	procedure SetAdapterName(Value: String);
	procedure SetAdapterDescription(Value: String);
	procedure DoOpen(Source: PChar; Auth: ppcap_rmtauth; Dev: ppcap_if_t);
	procedure CreateSnoopThread;
  protected
	// used internally
	FThread: TSnoopThread;
	FPcap: PPcap;
	FPacketHeader: PPCAP_PKTHDR;
	FPacketData: PETHERNET_HDR;
	procedure OnCaptureCB; virtual; abstract;
	procedure ThreadTerminate(Sender:TObject);
  //procedure GetAdapters;
	procedure GetAdapterNames;
	procedure GetAdapterDescriptions;
	function ProcessFilter(Dev: ppcap_if_t): Boolean;
  public
	constructor Create;//override;
	destructor Destroy; override;
	procedure Open; overload;
	procedure Open(Host: String; UserName: String; Password: String); overload;
	function LoadFromFile(FileName: String): Boolean;
	procedure Close;
  public
	property Active: Boolean read FActive;
	property Pcap: PPcap read FPcap write FPcap;
  //property Adapters: TStringList read FAdapters;
	property AdapterNames: TStringList read FAdapterNames;
	property AdapterDescriptions: TStringList read FAdapterDescriptions;
	property Error: String read FError write FError;
  property Version: String read Fversion;
	property SourceName: String read FSourceName;
  published
	property AdapterIndex: Integer read FAdapterIndex write SetAdapterIndex;
	property AdapterName: String read FAdapterName write SetAdapterName;
	property AdapterDescription: String read FAdapterDescription write SetAdapterDescription;
	property ThreadSafe: Boolean read FThreadSafe write FThreadSafe;
	property Filter: String read FFilter write FFilter;
	property SnapLen: Integer read FSnapLen write FSnapLen;
	property Flags: Integer read FFlags write FFlags;
	property ReadTimeOut: Integer read FReadTimeOut write FReadTimeOut;
	property OnGetRemoteAdapterInfo: TOnGetRemoteAdapterInfo read
		FOnGetRemoteAdapterInfo write FOnGetRemoteAdapterInfo;
  end;

TSnoop = class(TCustomSnoop)
  protected
	// property
	FOnCapture: TOnCaptureEvent;
  protected
	// used internally
	procedure OnCaptureCB; override;
  public
	constructor Create; //override;
  published
	property OnCapture: TOnCaptureEvent read FOnCapture write FOnCapture;
  end;

  TPacketBuffer = Array[0..(1024*64)-1] of byte;

// ----------------------------------------------------------------------------
// General Functions
// ----------------------------------------------------------------------------
function snoopIsIP(EthernetHeader: PETHERNET_HDR; IPHeader: PPIP_HDR = nil): Boolean;
function snoopIsARP(EthernetHeader: PETHERNET_HDR; ARPHeader: PPARP_HDR= nil): Boolean;
function snoopIsRARP(EthernetHeader: PETHERNET_HDR; ARPHeader: PPARP_HDR= nil): Boolean;
function snoopIsICMP(IPHeader: PIP_Hdr; ICMPHeader: PPICMP_HDR = nil): Boolean;
function snoopIsTCP(IPHeader: PIP_HDR; TCPHeader: PPTCP_HDR = nil): Boolean;
function snoopIsUDP(IPHeader: PIP_HDR; UDPHeader: PPUDP_HDR = nil): Boolean;
function snoopIsTCPData(IPHeader: PIP_HDR; TCPHeader: PTCP_HDR; TCPData: PPChar = nil; TCPDataLength: PInteger = nil): Boolean;
function snoopIsUDPData(IPHeader: PIP_HDR; UDPHeader: PUDP_HDR; UDPData: PPChar = nil; UDPDataLength: PInteger = nil): Boolean;
function snoopMac2Str(Mac: SNOOPMACADDRESS): String;
function snoopIP2Str(IP: DWORD): String;
function snoopStr2Mac(s: String): SNOOPMACADDRESS;
function snoopStr2IP(s: String): DWORD;
function snoopCleanMac: SNOOPMACADDRESS;
function snoopIsCleanMac(Mac: PSNOOPMACADDRESS): Boolean; overload;
function snoopCompareMac(Mac1: PSNOOPMACADDRESS; Mac2: PSNOOPMACADDRESS): Integer;
function snoopIPChecksum(IPHeader: PIP_HDR): WORD;
function snoopTCPChecksum(IPHeader: PIP_HDR; TCPHeader: PTCP_HDR): WORD;
function snoopUDPChecksum(IPHeader: PIP_HDR; UDPHeader: PUDP_HDR): WORD;
function snoopSendPacket(Pcap: PPcap; Buffer: PChar; Size: Integer): Integer;
//
function send_arpreply(pcap:ppcap;mac_src,mac_dest:array of byte;ip_src,ip_dest:string):integer;
function send_arprequest(pcap:ppcap;mac_src,mac_dest:array of byte;ip_src,ip_dest:string):integer;

function send_rarprequest(pcap:ppcap;mac_src,mac_dest,mac_to_find:array of byte;ip_src,ip_dest:string):integer;
function send_rarpreply(pcap:ppcap;mac_src,mac_dest,mac_to_find:array of byte;ip_found,ip_src:string):integer;


procedure buildarpreply
(mac_src,mac_dest:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);

procedure buildarprequest
(mac_src,mac_dest:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);

 procedure buildrarprequest
(mac_src,mac_dest,mac_to_find:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);

 procedure buildrarpreply
(mac_src,mac_dest,mac_to_find:array of byte;
 ip_found,ip_src:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);

function GetRemoteAdapterDescriptions(source:pchar;username,password:string;var AdapterDescriptions:tstringlist):string;

implementation

uses Bpf,SysUtils,Dialogs;

//************************************
constructor TSnoopAdapter.Create(const Adescription,AName: String;Aindex:dword) ;
begin
   inherited Create;
   FDescription := Adescription;
   Fname := AName;
   Findex := Aindex;
end;
//************************************

// ----------------------------------------------------------------------------
// TSnoopThread Class
// ----------------------------------------------------------------------------
constructor TSnoopThread.Create(Snoop: TCustomSnoop);
begin
	FSnoop := Snoop;
	inherited Create(true);
end;

destructor TSnoopThread.Destroy;
begin
	inherited;
end;

procedure TSnoopThread.Open;
begin
	Resume;
end;

procedure TSnoopThread.Close;
begin
	Terminate;
	WaitFor;
end;

procedure TSnoopThread.Execute;
var
	i: Integer;
	Pcap: PPcap;
	PacketHeader: PPCAP_PKTHDR;
	PacketData: PETHERNET_HDR;
	Snoop: TCustomSnoop;
begin
	Snoop := FSnoop; // use local variable for execute optimization
	if Snoop = nil then
		exit;
	Pcap := Snoop.Pcap;
	while not Terminated do
	begin
		i := pcap_next_ex(Pcap, @PacketHeader, @PacketData);
		if Terminated {or Application.Terminated} then break;
		case i of
			-1: begin// if an error occurred
				FSnoop.FError := 'Snoop Error: pcap_next_ex return -1';
				break;
			end;
			0: continue; // if the timeout set with pcap_open_live() has elapsed.
		end;
		Snoop.FPacketHeader := PacketHeader;
		Snoop.FPacketData := PacketData;
		if Snoop.ThreadSafe then
			Synchronize(Snoop.OnCaptureCB)
		else
			Snoop.OnCaptureCB;
	end;
end;

// ----------------------------------------------------------------------------
// TCustomSnoop Class
// ----------------------------------------------------------------------------
{
procedure TCustomSnoop.OnCaptureCB;
begin
end;
}

procedure TCustomSnoop.ThreadTerminate(Sender:TObject);
begin
	FActive := false;
	pcap_close(FPcap);
end;

{
procedure TCustomSnoop.GetAdapters;
var
	i: Integer;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
begin
	if AdapterDescriptions = nil then exit;
	AdapterDescriptions.Capacity:= 10;
	AdapterDescriptions.Sorted:= false;
	i := pcap_findalldevs(@AllDevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
		Error := ErrBuf;
		exit;
	end;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		Adapters.Add(Dev^.description);
		Dev := Dev^.next;
	end;
	FError := '';
	pcap_freealldevs(AllDevs);
end;
}

procedure TCustomSnoop.GetAdapterNames;
var
	i: Integer;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
begin
	if AdapterNames = nil then exit;
	AdapterNames.Capacity:= 10;
	AdapterNames.Sorted:= false;
	i := pcap_findalldevs(@AllDevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
                //raise exception.create(errbuf);
                Error := ErrBuf;
		exit;
	end;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		AdapterNames.Add(Dev^.name);
                //showmessage(dev^.name);
		Dev := Dev^.next;
	end;
	FError := '';
	pcap_freealldevs(AllDevs);
end;



procedure TCustomSnoop.GetAdapterDescriptions;
var
	i: Integer;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
begin
	if AdapterDescriptions = nil then exit;
	AdapterDescriptions.Capacity:= 10;
	AdapterDescriptions.Sorted:= false;
	i := pcap_findalldevs(@AllDevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
		Error := ErrBuf;
		exit;
	end;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		AdapterDescriptions.Add(Dev^.description);
		Dev := Dev^.next;
	end;
	FError := '';
	pcap_freealldevs(AllDevs);
end;

function TCustomSnoop.ProcessFilter(Dev: ppcap_if_t): Boolean;
var
	NetMask: u_int;
	FCode: bpf_program;
begin
	Result := false;
	if (Dev <> nil) and (Dev^.address <> nil) then
		NetMask := Dev^.address.netmask.sin_addr.S_addr
	else
		NetMask := $FFFFFFFF;
	if pcap_compile(FPcap, @FCode, PChar(FFilter), 1, NetMask) < 0  then
	begin
		FError := String(pcap_geterr(FPcap));
		exit;
	end;
	if pcap_setfilter(FPcap, @FCode) < 0 then
	begin
		FError := String(pcap_geterr(FPcap));
		exit;
	end;
	Result := true;
end;

procedure TCustomSnoop.SetAdapterIndex(Value: Integer);
begin
	if Value = FAdapterIndex then
		exit;
	if (Value < 0) or (Value >= FAdapterNames.Count) then
	begin
		FAdapterIndex := -1;
		FAdapterName := '';
	end else
	begin
		FAdapterIndex := Value;
		FAdapterName := FAdapterNames[Value];
		FAdapterDescription := FAdapterDescriptions[Value];
	end;
end;

procedure TCustomSnoop.SetAdapterName(Value: String);
var
	i: Integer;
begin
	if Value = FAdapterName then
		exit;
	for i := 0 to FAdapterNames.Count -1 do
	begin
		if Value = FAdapterNames[i] then
		begin
			FAdapterIndex := i;
			FAdapterName := FAdapterNames[i];
			FAdapterDescription := FAdapterDescriptions[i];
			exit;
		end;
	end;
	FAdapterIndex := -1;
	FAdapterName := '';
	FAdapterDescription := '';
end;

procedure TCustomSnoop.SetAdapterDescription(Value: String);
var
	i: Integer;
begin
	if Value = FAdapterDescription then
		exit;
	for i := 0 to FAdapterDescriptions.Count -1 do
	begin
		if Value = FAdapterDescriptions[i] then
		begin
			FAdapterIndex := i;
			FAdapterName := FAdapterNames[i];
			FAdapterDescription := FAdapterDescriptions[i];
			exit;
		end;
	end;
	FAdapterIndex := -1;
	FAdapterName := '';
	FAdapterDescription := '';
end;

procedure TCustomSnoop.DoOpen(Source: PChar; Auth: ppcap_rmtauth; Dev: ppcap_if_t);
var
	ErrBuf: array [0 .. PCAP_ERRBUF_SIZE - 1] of Char;
begin
	FPcap := pcap_open(Source, FSnapLen, FFlags, FReadTimeOut, Auth, ErrBuf);
	if FPcap = nil then
	begin
		FError := ErrBuf;
		exit;
	end;
  //pcap_setbuff (fpcap,512*1024);
	FSourceName := String(Source);
	if not ProcessFilter(Dev) then exit;
	FActive := true;
end;

procedure TCustomSnoop.CreateSnoopThread;
begin
	// Start Snoop Read Thread
	FThread := TSnoopThread.Create(Self);
	FThread.OnTerminate := ThreadTerminate;
	FThread.FreeOnTerminate := false;
	FThread.Resume;
end;

constructor TCustomSnoop.Create();
begin
	inherited;
	FActive := false;
	FAdapterIndex := -1;
	FAdapterName := '';
	FAdapterNames := TStringList.Create;
	GetAdapterNames;
	FAdapterDescriptions := TStringList.Create;
	GetAdapterDescriptions;
	if FError <> '' then
	begin
        {
		if not (csDesigning in ComponentState) then
			ShowMessage(FError);
        }
	end;
	FThreadSafe := true;
	FFilter := '';
	FSnapLen := SNOOP_DEFAULT_SNAPLEN;
	FFlags := PCAP_OPENFLAG_PROMISCUOUS;
	FReadTimeOut := 100;
	FError := '';
	FThread := nil;
	FPcap := nil;
end;

destructor TCustomSnoop.Destroy;
begin
	Close;
	if FAdapterNames <> nil then
	begin
		FAdapterNames.Free;
		FAdapterNames := nil;
	end;
	inherited;
end;

procedure TCustomSnoop.Open;
var
	i: Integer;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
begin
	if FActive then
	begin
		FError := 'Snoop Error: Already open';
		exit;
	end;
	i := pcap_findalldevs(@AllDevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
		Error := ErrBuf;
		exit;
	end;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		if StrComp(Dev^.name, PChar(FAdapterName)) = 0 then break;
		Dev := Dev^.next;
	end;
	if Dev = nil then
		FError := 'Snoop Error: Invalid AdapterName'
	else
	begin
		DoOpen(PChar(FAdapterName), nil, Dev);
		if FActive then
			CreateSnoopThread;
	end;
	pcap_freealldevs(AllDevs);
end;

procedure TCustomSnoop.Open(Host: String; UserName: String; Password: String);
var
	i: Integer;
	Source: String;
	AdapterIndex: Integer;
	Auth: pcap_rmtauth;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
	AdapterNames: TStringList;
	AdapterDescriptions: TStringList;
begin
	if FActive then
	begin
		FError := 'Snoop Error: Already open';
		exit;
	end;
	Source := 'rpcap://' + Host + '/';
	Auth.type_ := RPCAP_RMTAUTH_PWD;
	Auth.username := PChar(UserName);
	Auth.password := PChar(Password);
	i := pcap_findalldevs_ex(PChar(Source), @Auth, @Alldevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
		Error := ErrBuf;
		exit;
	end;
	AdapterNames := TStringList.Create;
	AdapterDescriptions := TStringList.Create;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		AdapterNames.Add(Dev^.name);
		AdapterDescriptions.Add(Dev^.description);
		Dev := Dev^.next;
	end;
	AdapterIndex := -1;
	if @FOnGetRemoteAdapterInfo <> nil then
		FOnGetRemoteAdapterInfo( AdapterNames, AdapterDescriptions, AdapterIndex);
	if AdapterIndex <> -1 then Dev := AllDevs;
	for i := 0 to AdapterIndex - 1 do Dev := Dev^.next;
	if Dev = nil then
		FError := 'Snoop Error: Cancel By User or Invalid AdapterName'
	else
	begin
		Source := Dev^.name;
		DoOpen(PChar(Source), @Auth, Dev);
		if FActive then
			CreateSnoopThread;
	end;
	pcap_freealldevs(AllDevs);
end;

function TCustomSnoop.LoadFromFile(FileName: String): Boolean;
var
	i: Integer;
	Pcap: PPcap;
	PacketHeader: PPCAP_PKTHDR;
	PacketData: PETHERNET_HDR;
begin
	Result := false;
	if FActive then
	begin
		FError := 'Snoop Error: Already open';
		exit;
	end;
	if FileName = '' then
	begin
		FError := 'Snoop Error: Invalid FileName';
		exit;
	end;
	DoOpen(PChar('file://' + FileName), nil, nil);
	if not FActive then exit;
	Pcap := Self.FPcap;
	while true do
	begin
		i := pcap_next_ex(Pcap, @PacketHeader, @PacketData);
		case i of
			-2: break; // EOF was reached reading from an offline capture
			-1: begin// if an error occurred
				FError := 'Snoop Error: pcap_next_ex return -1';
				break;
			end;
			0: begin
				//snoopGTrace('[Snoop.pas] Oh, impossible brance(pcap_next_ex)'); // gilgil temp 2003.08.05
				continue; // if the timeout set with pcap_open_live() has elapsed.
			end;
		end;
		FPacketHeader := PacketHeader;
		FPacketData := PacketData;
		OnCaptureCB;
	end;
	FActive := false;
	pcap_close(Pcap);
	Result := true;
end;

procedure TCustomSnoop.Close;
begin
	if not FActive then
		exit;
	if FThread = nil then
	begin
		FError := 'Snoop Error: No thread to stop';
		//raise exception.create(FError);
		exit;
	end;
	FActive := false;
	// Stop Snooping Thread
	FThread.Close;
	FThread.Free;
	FThread := nil;
end;

// ----------------------------------------------------------------------------
// TSnoop Class
// ----------------------------------------------------------------------------
procedure TSnoop.OnCaptureCB;
begin
	if @FOnCapture = nil then exit;
	FOnCapture( FPacketHeader, FPacketData);
end;

constructor TSnoop.Create;
var ret:boolean;
begin
        //api is dynamicaly loaded on create
        ret:= initapi;
        if ret=false
          then raise Ewin32error.Create ('loadlibrary(''wpcap.dll'') failed')
          else Fversion :=pcap_lib_version ;
	inherited;

end;


// ----------------------------------------------------------------------------
// General Functions
// ----------------------------------------------------------------------------
function snoopIsIP(EthernetHeader: PETHERNET_HDR; IPHeader: PPIP_HDR): Boolean;
begin
	Result := false;
	if ntohs(EthernetHeader.Protocol) <> PROTO_IP then
		exit;
	if IPHeader <> nil then
		IPHeader^ := PIP_HDR(DWORD(EthernetHeader) + sizeof(ETHERNET_HDR));
	Result := true;
end;

function snoopIsARP(EthernetHeader: PETHERNET_HDR; ARPHeader: PPARP_HDR): Boolean;
begin
	Result := false;
	if ntohs(EthernetHeader.Protocol) <> PROTO_ARP then
		exit;
	if ARPHeader <> nil then
		ARPHeader^ := PARP_HDR(DWORD(EthernetHeader) + sizeof(ETHERNET_HDR));
	Result := true;
end;

function snoopIsRARP(EthernetHeader: PETHERNET_HDR; ARPHeader: PPARP_HDR): Boolean;
begin
	Result := false;
	if ntohs(EthernetHeader.Protocol) <> PROTO_RARP then
		exit;
	if ARPHeader <> nil then
		ARPHeader^ := PARP_HDR(DWORD(EthernetHeader) + sizeof(ETHERNET_HDR));
	Result := true;
end;

function snoopIsICMP(IPHeader: PIP_Hdr; ICMPHeader: PPICMP_HDR): Boolean;
begin
	Result := false;
	if IPHeader.Protocol <> PROTO_ICMP then
		exit;
	if ICMPHeader <> nil then
		ICMPHeader^ := PICMP_HDR(DWORD(IPHeader) + sizeof(IP_HDR));
	Result := true;
end;

function snoopIsTCP(IPHeader: PIP_HDR; TCPHeader: PPTCP_HDR): Boolean;
begin
	Result := false;
	if IPHeader.Protocol <> PROTO_TCP then
		exit;
	if TCPHeader <> nil then
		TCPHeader^ := PTCP_HDR(DWORD(IPHeader) + sizeof(IP_HDR));
	Result := true;
end;

function snoopIsUDP(IPHeader: PIP_HDR; UDPHeader: PPUDP_HDR): Boolean;
begin
	Result := false;
	if IPHeader.Protocol <> PROTO_UDP then exit;
	if UDPHeader <> nil then
		UDPHeader^ := PUDP_HDR(DWORD(IPHeader) + sizeof(TCP_HDR));
	Result := true;
end;

function snoopIsTCPData(IPHeader: PIP_HDR; TCPHeader: PTCP_HDR; TCPData: PPChar; TCPDataLength: PInteger): Boolean;
var
	_TCPHeaderLength: Integer;
	_Data: PChar;
	_Length: Integer;
begin
	_TCPHeaderLength := ((TCPHeader.Off_Rsvd and $F0) shr 4) * sizeof(DWORD);
	_Data := PChar(DWORD(TCPHeader) + DWORD(_TCPHeaderLength));
	_Length := ntohs(IPHeader.Length) - sizeof(TCP_HDR) - _TCPHeaderLength;
	if TCPData <> nil then TCPData^ := _Data;
	if TCPDataLength <> nil then TCPDataLength^ := _Length;
	Result := _Length > 0;
end;

function snoopIsUDPData(IPHeader: PIP_HDR; UDPHeader: PUDP_HDR; UDPData: PPChar; UDPDataLength: PInteger): Boolean;
begin
	if UDPData <> nil then
		UDPData^ := PChar(DWORD(UDPHeader) + sizeof(UDP_HDR));
	if UDPDataLength <> nil then
		UDPDataLength^ := ntohs(UDPHeader.Length) - sizeof(UDP_HDR);
	Result := true;
end;

function snoopMac2Str(Mac: SNOOPMACADDRESS): String;
var
	ch1, ch2: Byte;
	i: Integer;
begin
	Result := '';
	for i := 0 to SNOOP_MAC_SIZE - 1 do
	begin
		ch1 := Mac[i] and $F0;
		ch1 := ch1 shr 4;
		if ch1 > 9 then
			ch1 := ch1 + Ord('A') - 10
		else
			ch1 := ch1 + Ord('0');
		ch2 := Mac[i] and $0F;
		if ch2 > 9 then
			ch2 := ch2 + Ord('A') - 10
		else
			ch2 := ch2 + Ord('0');
		Result := Result + Chr(ch1) + Chr(ch2);
		if i = 2 then
			Result := Result + '-';
	end;
end;

function snoopIP2Str(IP: DWORD): String;
begin
	Result := Format('%d.%d.%d.%d', [
		(IP and $FF000000) shr 24,
		(IP and $00FF0000) shr 16,
		(IP and $0000FF00) shr 8,
		(IP and $000000FF) shr 0
	]);
end;

function snoopStr2Mac(s: String): SNOOPMACADDRESS;
var
	i: Integer;
	Index: Integer;
	Ch: String;
	Mac: SNOOPMACADDRESS;
begin
	Index := 1;
	for i := 0 to SNOOP_MAC_SIZE - 1 do
	begin
		Ch := Copy(s, Index, 2);
		Mac[i] := StrToInt('$' + Ch);
		inc(Index, 2);
		while s[Index] = '-' do
			inc(Index);
	end;
	Result := Mac;
end;

function snoopStr2IP(s: String): DWORD;
var
	i: Integer;
	Index: Integer;
	Digit: String;
	IP: array [0 .. 4 - 1] of DWORD;
	Len: Integer;
begin
	Index := 1;
	for i := 0 to 4 - 1 do
		IP[i] := 0;
	Len := Length(s);
	for i := 0 to 4 - 1 do
	begin
		Digit := '';
		while(s[Index] >= '0') and (s[Index] <= '9') and (Index <= Len) do
		begin
			Digit := Digit + s[Index];
			inc(Index);
		end;
		inc(Index);
		IP[i] := StrToInt(Digit);
	end;
	Result :=
		IP[0] shl 24 +
		IP[1] shl 16 +
		IP[2] shl 8 +
		IP[3] shl 0;
end;

function snoopCleanMac: SNOOPMACADDRESS;
var
	i: Integer;
begin
	for i := 0 to SNOOP_MAC_SIZE - 1 do
		Result[i] := 0;
end;

function snoopIsCleanMac(Mac: PSNOOPMACADDRESS): Boolean;
var
	i: Integer;
begin
	Result := true;
	for i := 0 to SNOOP_MAC_SIZE - 1 do
		if Mac[i] <> 0 then
		begin
			Result := false;
			exit;
		end;
end;

function snoopCompareMac(Mac1: PSNOOPMACADDRESS; Mac2: PSNOOPMACADDRESS): Integer;
var
	i: Integer;
begin
	for i := 0 to SNOOP_MAC_SIZE - 1 do
	begin
		if Mac1[i] = Mac2[i] then continue;
		if Mac1[i] > Mac2[i] then
		begin
			Result := 1;
			exit;
		end else
		begin
			Result := -1;
			exit;
		end;
	end;
	Result := 0;
end;

function snoopIPChecksum(IPHeader: PIP_HDR): WORD;
var
	i: Integer;
	p: PWORD;
	Sum: DWORD;
begin
	p := PWORD(IPHeader);
	Sum := 0;
	// Add IPHeader Buffer as array of WORD
	for i := 0 to sizeof(IP_HDR) div 2 - 1do
	begin
		Sum := Sum + ntohs(p^);
		inc(p);
	end;
	// Treat Checksum field as 0
	Sum := Sum - ntohs(IPHeader.Checksum);
	// Recalculate Sum
	while (Sum shr 16) > 0 do
		Sum := (Sum and $FFFF) + (Sum shr 16);
	Sum := not Sum;
	Result := Sum;
end;

function snoopTCPChecksum(IPHeader: PIP_HDR; TCPHeader: PTCP_HDR): WORD;
var
	i: Integer;
	TCPHeaderDataLength: Integer;
	p: PWORD;
	Source, Destination: DWORD;
	Sum: DWORD;
begin
	TCPHeaderDataLength := ntohs(IPHeader.Length) - sizeof(IP_HDR);
	Sum := 0;
	// Add TCPHeader and Data Buffer as array of WORD
	p := PWORD(TCPHeader);
	for i := 0 to TCPHeaderDataLength div 2 - 1 do
	begin
		Sum := Sum + htons(p^);
		inc(p);
	end;
	// if Length is OddNumber, Add Last Data
	if (TCPHeaderDataLength div 2) * 2 <> TCPHeaderDataLength then
		Sum := Sum + (htons(p^) and $FF00);
	// Treat Checksum field as 0
	Sum := Sum - ntohs(TCPHeader.Checksum);
	// Add Source Address
	Source := ntohl(IPHeader.Source);
	Sum := Sum + ((Source and $FFFF0000) shr 16) + (Source and $0000FFFF);
	// Add Destination Addres
	Destination := ntohl(IPHeader.Destination);
	Sum := Sum + ((Destination and $FFFF0000) shr 16) + (Destination and $0000FFFF);
	// Add Extra Information
	Sum := Sum + PROTO_TCP + DWORD(TCPHeaderDataLength);
	// Recalculate Sum
	while (Sum shr 16) > 0 do
		Sum := (Sum and $FFFF) + (Sum shr 16);
	Sum := not Sum;
	Result := Sum;
end;

function snoopUDPChecksum(IPHeader: PIP_HDR; UDPHeader: PUDP_HDR): WORD;
var
	i: Integer;
	UDPHeaderDataLength: Integer;
	p: PWORD;
	Source, Destination: DWORD;
	Sum: DWORD;
begin
	UDPHeaderDataLength := ntohs(UDPHeader.Length);
	Sum := 0;
	// Add UDPHeader and Data Buffer as array of WORD
	p := PWORD(UDPHeader);
	for i := 0 to UDPHeaderDataLength div 2 - 1 do
	begin
		Sum := Sum + htons(p^);
		inc(p);
	end;
	// if Length is OddNumber, Add Last Data
	if (UDPHeaderDataLength div 2) * 2 <> UDPHeaderDataLength then
		Sum := Sum + (htons(p^) and $FF00);
	// Treat Checksum field as 0
	Sum := Sum - ntohs(UDPHeader.Checksum);
	// Add Source Address
	Source := ntohl(IPHeader.Source);
	Sum := Sum + ((Source and $FFFF0000) shr 16) + (Source and $0000FFFF);
	// Add Destination Addres
	Destination := ntohl(IPHeader.Destination);
	Sum := Sum + ((Destination and $FFFF0000) shr 16) + (Destination and $0000FFFF);
	// Add Extra Information
	Sum := Sum + PROTO_UDP + DWORD(UDPHeaderDataLength);
	// Recalculate Sum
	while (Sum shr 16) > 0 do
		Sum := (Sum and $FFFF) + (Sum shr 16);
	Sum := not Sum;
	Result := Sum;
end;

procedure buildarpreply
(mac_src,mac_dest:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);
var
arp_buf,eth_buf: array[0..4096-1 ] of byte;
i:byte;
begin
//ethernet header
fillchar(eth_buf,sizeof(eth_buf),0);
//ff ff ff ff ff ff -> to all network
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Destination[i]:=mac_dest[i];
//for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source[i]:=$ff;
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source [i]:=mac_src[i];
PETHERNET_HDR(@eth_buf).protocol:=ntohs($0806);
//arp reply
fillchar(arp_buf,sizeof(arp_buf),0);
PARP_HDR(@arp_buf).HardwareType :=ntohs($0001);
PARP_HDR(@arp_buf).ProtocolType :=ntohs($0800);
PARP_HDR(@arp_buf).HLen :=$6;
PARP_HDR(@arp_buf).PLen :=$4;
PARP_HDR(@arp_buf).Operation :=ntohs($0002);
for i:=0 to 5 do PARP_HDR(@arp_buf).SenderHA [i]:=mac_src[i];
PARP_HDR(@arp_buf).SenderIP :=inet_Addr(PansiChar(ip_src));;
for i:=0 to 5 do PARP_HDR(@arp_buf).TargetHA [i]:=mac_dest[i]; //0;
PARP_HDR(@arp_buf).TargetIP :=inet_Addr(PansiChar(ip_dest));;
//fill buffer
fillchar(buf,sizeof(buf),0);
CopyMemory ( @buf[0],@eth_buf,14);
CopyMemory ( @buf[14],@arp_buf,sizeof(ARP_HDR));
iTotalSize:=14+sizeof(ARP_HDR);
end;


function send_arpreply(pcap:ppcap;mac_src,mac_dest:array of byte;ip_src,ip_dest:string):integer;
var
buf: tpacketbuffer; //array[0..4096-1 ] of byte;
ret:integer;
isize:word;
e:string;
begin
buildarpreply(mac_src,mac_dest,ip_src,ip_dest,buf,isize);
ret:=usnoop.snoopSendPacket(pcap,@buf[0],isize);
result:=ret;
end;

function send_rarprequest(pcap:ppcap;mac_src,mac_dest,mac_to_find:array of byte;ip_src,ip_dest:string):integer;
var
buf: tpacketbuffer; //array[0..4096-1 ] of byte;
ret:integer;
isize:word;
e:string;
begin

buildrarprequest(mac_src,mac_dest,mac_to_find,ip_src,ip_dest,buf,isize);
ret:=usnoop.snoopSendPacket(pcap,@buf[0],isize);
result:=ret;
//raw_sniffer.writepacket(e,false,buf,14+sizeof(tarp_header));

end;

function send_rarpreply(pcap:ppcap;mac_src,mac_dest,mac_to_find:array of byte;ip_found,ip_src:string):integer;
var
buf: tpacketbuffer; //array[0..4096-1 ] of byte;
ret:integer;
isize:word;
e:string;
begin

buildrarpreply(mac_src,mac_dest,mac_to_find,ip_found,ip_src,buf,isize);
ret:=usnoop.snoopSendPacket(pcap,@buf[0],isize);
result:=ret;


end;


procedure buildrarpreply
(mac_src,mac_dest,mac_to_find:array of byte;
 ip_found,ip_src:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);
var
arp_buf,eth_buf: array[0..4096-1 ] of byte;
i:byte;
begin
//ethernet header
fillchar(eth_buf,sizeof(eth_buf),0);
//ff ff ff ff ff ff -> to all network
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Destination[i]:=mac_dest[i];
//for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source[i]:=$ff;
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source [i]:=mac_src[i];
PETHERNET_HDR(@eth_buf).protocol:=ntohs($8035);
//arp reply
fillchar(arp_buf,sizeof(arp_buf),0);
PARP_HDR(@arp_buf).HardwareType :=ntohs($0001);
PARP_HDR(@arp_buf).ProtocolType :=ntohs($0800);
PARP_HDR(@arp_buf).HLen :=$6;
PARP_HDR(@arp_buf).PLen :=$4;
PARP_HDR(@arp_buf).Operation :=ntohs($0004); //Request
for i:=0 to 5 do PARP_HDR(@arp_buf).SenderHA [i]:=mac_src[i];
PARP_HDR(@arp_buf).SenderIP :=inet_Addr(PansiChar(ip_src));;
for i:=0 to 5 do PARP_HDR(@arp_buf).TargetHA [i]:=mac_to_find[i];
PARP_HDR(@arp_buf).TargetIP :=inet_Addr(PansiChar(ip_found));
//fill buffer
fillchar(buf,sizeof(buf),0);
CopyMemory ( @buf[0],@eth_buf,14);
CopyMemory ( @buf[14],@arp_buf,sizeof(ARP_HDR));
iTotalSize:=14+sizeof(ARP_HDR);
end;


procedure buildrarprequest
(mac_src,mac_dest,mac_to_find:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);
var
arp_buf,eth_buf: array[0..4096-1 ] of byte;
i:byte;
begin
//ethernet header
fillchar(eth_buf,sizeof(eth_buf),0);
//ff ff ff ff ff ff -> to all network
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Destination[i]:=mac_dest[i];
//for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source[i]:=$ff;
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source [i]:=mac_src[i];
PETHERNET_HDR(@eth_buf).protocol:=ntohs($8035);   //$8035??
//arp reply
fillchar(arp_buf,sizeof(arp_buf),0);
PARP_HDR(@arp_buf).HardwareType :=ntohs($0001);
PARP_HDR(@arp_buf).ProtocolType :=ntohs($0800);
PARP_HDR(@arp_buf).HLen :=$6;
PARP_HDR(@arp_buf).PLen :=$4;
PARP_HDR(@arp_buf).Operation :=ntohs($0003); //Request
for i:=0 to 5 do PARP_HDR(@arp_buf).SenderHA [i]:=mac_src[i];
PARP_HDR(@arp_buf).SenderIP :=inet_Addr(PansiChar(ip_src));;
for i:=0 to 5 do PARP_HDR(@arp_buf).TargetHA [i]:=mac_to_find[i];//mac_dest[i];
PARP_HDR(@arp_buf).TargetIP :=0; //inet_Addr(PChar(ip_dest));;
//fill buffer
fillchar(buf,sizeof(buf),0);
CopyMemory ( @buf[0],@eth_buf,14);
CopyMemory ( @buf[14],@arp_buf,sizeof(ARP_HDR));
iTotalSize:=14+sizeof(ARP_HDR);
end;




procedure buildarprequest
(mac_src,mac_dest:array of byte;
 ip_src,ip_dest:string;
 Var Buf         : TPacketBuffer;
 Var iTotalSize  : Word);
var
arp_buf,eth_buf: array[0..4096-1 ] of byte;
i:byte;
begin
//ethernet header
fillchar(eth_buf,sizeof(eth_buf),0);
//ff ff ff ff ff ff -> to all network
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Destination[i]:=mac_dest[i];
//for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source[i]:=$ff;
for i:=0 to 5 do PETHERNET_HDR(@eth_buf).Source [i]:=mac_src[i];
PETHERNET_HDR(@eth_buf).protocol:=ntohs($0806);
//ARP
fillchar(arp_buf,sizeof(arp_buf),0);
PARP_HDR(@arp_buf).HardwareType :=ntohs($0001);
PARP_HDR(@arp_buf).ProtocolType :=ntohs($0800);
PARP_HDR(@arp_buf).HLen :=$6;
PARP_HDR(@arp_buf).PLen :=$4;
PARP_HDR(@arp_buf).Operation :=ntohs($0001); //request
for i:=0 to 5 do PARP_HDR(@arp_buf).SenderHA [i]:=mac_src[i];
PARP_HDR(@arp_buf).SenderIP :=inet_Addr(PansiChar(ip_src));;
//for i:=0 to 5 do PARP_HDR(@arp_buf).TargetHA [i]:=0;
for i:=0 to 5 do PARP_HDR(@arp_buf).TargetHA [i]:=mac_dest[i];
PARP_HDR(@arp_buf).TargetIP :=inet_Addr(PansiChar(ip_dest));;
//fill buffer
fillchar(buf,sizeof(buf),0);
CopyMemory ( @buf[0],@eth_buf,14);
CopyMemory ( @buf[14],@arp_buf,sizeof(ARP_HDR));
iTotalSize:=14+sizeof(ARP_HDR);
end;

function send_arprequest(pcap:ppcap;mac_src,mac_dest:array of byte;ip_src,ip_dest:string):integer;
var
buf: tpacketbuffer; //array[0..4096-1 ] of byte;
ret:integer;
isize:word;
e:string;
begin

buildarprequest(mac_src,mac_dest,ip_src,ip_dest,buf,isize);
ret:=usnoop.snoopSendPacket(pcap,@buf[0],isize);
result:=ret;
//raw_sniffer.writepacket(e,false,buf,14+sizeof(tarp_header));

end;


function snoopSendPacket(Pcap: PPcap; Buffer: PChar; Size: Integer): Integer;
begin
	Result := pcap_sendpacket(Pcap, Buffer, Size);
end;

function GetRemoteAdapterDescriptions(source:pchar;username,password:string;var AdapterDescriptions:tstringlist):string;
var
	i: Integer;
	Dev: ppcap_if_t;
	AllDevs: ppcap_if_t;
	ErrBuf: array[0 .. PCAP_ERRBUF_SIZE - 1] of Char;
	Auth: pcap_rmtauth;
  //AdapterDescriptions:tstringlist;
begin
	if AdapterDescriptions = nil then exit;
	AdapterDescriptions.Capacity:= 10;
	AdapterDescriptions.Sorted:= false;
  //
	Auth.type_ := RPCAP_RMTAUTH_PWD;
	Auth.username := PChar(UserName);
	Auth.password := PChar(Password);
  //
	i := pcap_findalldevs_ex(source,@Auth,@AllDevs, ErrBuf);
	if i <> 0 then // if error occured
	begin
		//Error := ErrBuf;
    result:=errbuf;
		exit;
	end;
	Dev := AllDevs;
	while Dev <> nil do
	begin
		AdapterDescriptions.Add('RPCAP - '+Dev^.description);
		Dev := Dev^.next;
	end;
	//FError := '';
  result:='';
	pcap_freealldevs(AllDevs);
end;

end.
