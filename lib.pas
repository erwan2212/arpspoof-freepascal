unit lib;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,iphlpapi,iptypes;

type AdapterInfo = record
adaptername:string;
Description:string;
AdrMac:string;
Index:string;
Type_:string;
AddressList:tstringlist;
AddressMaskList:tstringlist;
GatewayList:tstringlist;
DhcpEnabled:boolean;
DhcpServerAddress:string;
LeaseObtained:string;
LeaseExpires:string;
HaveWins:boolean;
PrimaryWinsServer:string;
SecondaryWinsServer:string;
end;
type  TAdapterInfo= array of AdapterInfo;

  function GetAdaptersInfo_(var info:TAdapterInfo;name:string=''):integer;

implementation

function GetAdaptersInfo_(var info:TAdapterInfo;name:string=''):integer;
  var
   _info:TAdapterInfo;
   _info_len:integer;
   Hdl          : LongWord ;
   pAdapterInfo : PIpAdapterInfo ;
   pOutBufLen   : LongWord ;
   Ret          : LongWord ;
   ErrStr       : String ;
   lpMsgBuf     : PChar ;
   //NodeDHCP,NodeWINS,NodeIPs,NodeRacine   : ttreenode ;
   AdrMac       : String ;
   i            : Integer ;
   LeType       : String ;
   pIp          : PIpAddrString ;
   strIp        : String ;
   strNetMask   : String ;
  begin

   { Initialise le tableau de structure pointé par pAdapterInfo }
   Hdl := GlobalAlloc(GPTR,SizeOf(TIpAdapterInfo)) ;
   pAdapterInfo := PIpAdapterInfo(Hdl) ;
   ZeroMemory(pAdapterInfo,SizeOf(TIpAdapterInfo)) ;
   pOutBufLen := SizeOf(TIpAdapterInfo) ;
   Ret := GetAdaptersInfo(pAdapterInfo,pOutBufLen) ;
   If (Ret=ERROR_BUFFER_OVERFLOW) then
     begin
      GlobalFree(Hdl);
      Hdl := GlobalAlloc(GPTR,pOutBufLen) ;
      pAdapterInfo := PIpAdapterInfo(Hdl) ;
      ZeroMemory(pAdapterInfo,pOutBufLen) ;
     end
    else
   If Ret<>ERROR_SUCCESS then
     begin
      FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER OR FORMAT_MESSAGE_FROM_SYSTEM,nil, ret, 0, @lpMsgBuf, 0, nil );
      ErrStr := StrPas(lpMsgBuf) ;
      messageboxa(0,pansichar(ErrStr),'iptools',0) ;
      GlobalFree(Hdl) ;
      Exit ;
     end ;

   { Récupère les infos }
   Ret := GetAdaptersInfo(pAdapterInfo,pOutBufLen) ;
   If Ret<>ERROR_SUCCESS then
    begin
     GlobalFree(Hdl) ;
     Exit ;
    end ;

   { Affiche les informations dans un Treeview }
   _info_len:=0;

   while Assigned(pAdapterInfo) do
    begin
    if (name='') or ((name<>'') and (name=Trim(StrPas(pAdapterInfo^.AdapterName)))) then
    begin
    setlength(_info,_info_len+1);
     { Le noeud racine, avec le nom de l'adaptateur }
     _info[_info_len].adaptername :=Trim(StrPas(pAdapterInfo^.AdapterName));
     { Description }
     _info[_info_len].Description :=Trim(StrPas(pAdapterInfo^.Description));
     { Adresse MAC }
     AdrMac := '' ;
     For i:=0 to (pAdapterInfo^.AddressLength-1) do  AdrMac := AdrMac + IntToHex(pAdapterInfo^.Address[i],2);// + ':' ;
     //AdrMac := Copy(AdrMac,1,Length(AdrMac)-1) ; { Enlève le dernier : }
     _info[_info_len].AdrMac :=AdrMac;
     { L'index }
     _info[_info_len].Index :=IntToStr(pAdapterInfo^.Index);
     { Le type }
     Case pAdapterInfo^.Type_ of
      MIB_IF_TYPE_OTHER      : LeType := 'Other' ;
      MIB_IF_TYPE_ETHERNET   : LeType := 'Ethernet' ;
      MIB_IF_TYPE_TOKENRING  : LeType := 'Token Ring' ;
      MIB_IF_TYPE_FDDI       : Letype := 'FDDI' ;
      MIB_IF_TYPE_PPP        : LeType := 'PPP' ;
      MIB_IF_TYPE_LOOPBACK   : LeType := 'Loopback' ;
      MIB_IF_TYPE_SLIP       : LeType := 'SLIP' ;
      else LeType := IntToStr(pAdapterInfo^.Type_) ;
     end ;
     _info[_info_len].Type_ :=LeType;
     { Les adresses IP associées }
     strIp := Trim(StrPas(pAdapterInfo^.IpAddressList.IpAddress.S)) ;
     strNetMask := Trim(StrPas(pAdapterInfo^.IpAddressList.IpMask.S)) ;
     _info[_info_len].AddressList:=tstringlist.create;
     _info[_info_len].AddressList.Add (strIp);
     _info[_info_len].AddressMaskList:=tstringlist.create;
     _info[_info_len].AddressMaskList.Add (strNetMask );
     pIp := pAdapterInfo^.IpAddressList.Next ;
     while Assigned(pIp) do
      begin
       strIp := Trim(StrPas(pIp^.IpAddress.S)) ;
       strNetMask := Trim(StrPas(pIp^.IpMask.S)) ;
       _info[_info_len].AddressList.Add (strIp);
       _info[_info_len].AddressMaskList.Add (strNetMask );
       {Passe à l'adresse IP suivante }
       pIp := pIp^.Next ;
      end ;
     { La passerelle par défaut }
     _info[_info_len].GatewayList :=tstringlist.create;
     _info[_info_len].GatewayList.Add (Trim(StrPas(pAdapterInfo^.GatewayList.IpAddress.S)));
     { La configuration DHCP }
     If pAdapterInfo^.DhcpEnabled=1
      then
      begin
      _info[_info_len].DhcpEnabled:=true;
      _info[_info_len].DhcpServerAddress :=Trim(StrPas(pAdapterInfo^.DhcpServer.IpAddress.S));
     _info[_info_len].LeaseObtained :=IntToStr(pAdapterInfo^.LeaseObtained);
     _info[_info_len].LeaseExpires :=IntToStr(pAdapterInfo^.LeaseExpires);
     end;
     { La configuration WINS }
     If pAdapterInfo^.HaveWins
      then
      begin
      _info[_info_len].HaveWins :=true;
      _info[_info_len].PrimaryWinsServer :=Trim(StrPas(pAdapterInfo^.PrimaryWinsServer.IpAddress.S));
      _info[_info_len].SecondaryWinsServer :=Trim(StrPas(pAdapterInfo^.SecondaryWinsServer.IpAddress.S));
      end;
     end; //if name= ....
      { Passe à l'adaptateur suivant }
     pAdapterInfo := pAdapterInfo^.Next ;
    inc(_info_len);
    end ;
   info:=_info;
   result:=_info_len;
   { Libère pAdapterInfo }
   GlobalFree(Hdl) ;

  end;


end.

