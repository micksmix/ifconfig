program ifconfig;
{$APPTYPE CONSOLE}

uses
  SysUtils,
  Classes,
  Winsock,
  uAdapterInfo in 'uAdapterInfo.pas';

type
  TAdapterInfo = array of record
    dwIndex: longint;
    dwType: longint;
    dwMtu: longint;
    dwSpeed: extended;
    dwPhysAddrLen: longint;
    bPhysAddr: string;
    dwAdminStatus: longint;
    dwOperStatus: longint;
    dwLastChange: longint;
    dwInOctets: longint;
    dwInUcastPkts: longint;
    dwInNUcastPkts: longint;
    dwInDiscards: longint;
    dwInErrors: longint;
    dwInUnknownProtos: longint;
    dwOutOctets: longint;
    dwOutUcastPkts: longint;
    dwOutNUcastPkts: longint;
    dwOutDiscards: longint;
    dwOutErrors: longint;
    dwOutQLen: longint;
    dwDescrLen: longint;
    bDescr: string;
    sIpAddress: string;
    sIpMask: string;
  end;

function Get_EthernetAdapterDetail(var AdapterDataFound: TAdapterInfo): boolean;
var
  pIfTable          : ^_IfTable;
  pIpTable          : ^_IpAddrTable;
  ifTableSize, ipTableSize: longint;
  tmp               : string;
  i, j, k, m        : integer;
  ErrCode           : longint;
  sAddr, sMask      : in_addr;
  IPAddresses, IPMasks: TStringList;
  sIPAddressLine, sIPMaskLine: string;
  bResult           : boolean;
begin
  bResult := True; //default return value
  pIfTable := nil;
  pIpTable := nil;

  IPAddresses := TStringList.Create;
  IPMasks := TStringList.Create;

  try
    // First: just get the buffer size.
    // TableSize returns the size needed.
    ifTableSize := 0; // Set to zero so the GetIfTabel function
    // won't try to fill the buffer yet,
    // but only return the actual size it needs.
    GetIfTable(pIfTable, ifTableSize, 1);
    if (ifTableSize < SizeOf(MIB_IFROW) + Sizeof(longint)) then
    begin
      bResult := False;
      Result := bResult;
      Exit; // less than 1 table entry?!
    end;

    ipTableSize := 0;
    GetIpAddrTable(pIpTable, ipTableSize, 1);
    if (ipTableSize < SizeOf(MIB_IPADDRROW) + Sizeof(longint)) then
    begin
      bResult := False;
      Result := bResult;
      Exit; // less than 1 table entry?!
    end;

    // Second:
    // allocate memory for the buffer and retrieve the
    // entire table.
    GetMem(pIfTable, ifTableSize);
    ErrCode := GetIfTable(pIfTable, ifTableSize, 1);

    if ErrCode <> ERROR_SUCCESS then
    begin
      bResult := False;
      Result := bResult;
      Exit; // OK, that did not work.
      // Not enough memory i guess.
    end;

    GetMem(pIpTable, ipTableSize);
    ErrCode := GetIpAddrTable(pIpTable, ipTableSize, 1);

    if ErrCode <> ERROR_SUCCESS then
    begin
      bResult := False;
      Result := bResult;
      Exit;
    end;

    for k := 1 to pIpTable^.dwNumEntries do
    begin
      sAddr.S_addr := pIpTable^.table[k].dwAddr;
      sMask.S_addr := pIpTable^.table[k].dwMask;

      sIPAddressLine := Format('0x%8.8x', [(pIpTable^.table[k].dwIndex)]) +
      '=' + Format('%s', [inet_ntoa(sAddr)]);
      sIPMaskLine := Format('0x%8.8x', [(pIpTable^.table[k].dwIndex)]) +
      '=' + Format('%s', [inet_ntoa(sMask)]);

      IPAddresses.Add(sIPAddressLine);
      IPMasks.Add(sIPMaskLine);
    end;

    SetLength(AdapterDataFound, pIfTable^.nRows); //initialize the array or records
    for i := 1 to pIfTable^.nRows do
      try
        //if pIfTable^.ifRow[i].dwType=MIB_IF_TYPE_ETHERNET then
        //begin
        m := i - 1;
        AdapterDataFound[m].dwIndex := 4; //(pIfTable^.ifRow[i].dwIndex);
        AdapterDataFound[m].dwType := (pIfTable^.ifRow[i].dwType);
        AdapterDataFound[m].dwIndex := (pIfTable^.ifRow[i].dwIndex);
        AdapterDataFound[m].sIpAddress :=
          IPAddresses.Values[Format('0x%8.8x', [(pIfTable^.ifRow[i].dwIndex)])];
        AdapterDataFound[m].sIpMask :=
          IPMasks.Values[Format('0x%8.8x', [(pIfTable^.ifRow[i].dwIndex)])];
        AdapterDataFound[m].dwMtu := (pIfTable^.ifRow[i].dwMtu);
        AdapterDataFound[m].dwSpeed := (pIfTable^.ifRow[i].dwSpeed);
        AdapterDataFound[m].dwAdminStatus := (pIfTable^.ifRow[i].dwAdminStatus);
        AdapterDataFound[m].dwOperStatus := (pIfTable^.ifRow[i].dwOperStatus);
        AdapterDataFound[m].dwInUcastPkts := (pIfTable^.ifRow[i].dwInUcastPkts);
        AdapterDataFound[m].dwInNUcastPkts := (pIfTable^.ifRow[i].dwInNUcastPkts);
        AdapterDataFound[m].dwInDiscards := (pIfTable^.ifRow[i].dwInDiscards);
        AdapterDataFound[m].dwInErrors := (pIfTable^.ifRow[i].dwInErrors);
        AdapterDataFound[m].dwInUnknownProtos := (pIfTable^.ifRow[i].dwInUnknownProtos);
        AdapterDataFound[m].dwOutNUcastPkts := (pIfTable^.ifRow[i].dwOutNUcastPkts);
        AdapterDataFound[m].dwOutUcastPkts := (pIfTable^.ifRow[i].dwOutUcastPkts);
        AdapterDataFound[m].dwOutDiscards := (pIfTable^.ifRow[i].dwOutDiscards);
        AdapterDataFound[m].dwOutErrors := (pIfTable^.ifRow[i].dwOutErrors);
        AdapterDataFound[m].dwOutQLen := (pIfTable^.ifRow[i].dwOutQLen);
        AdapterDataFound[m].bDescr := (pIfTable^.ifRow[i].bDescr);

        tmp := '';
        for j := 0 to pIfTable^.ifRow[i].dwPhysAddrLen - 1 do
        begin
          if Length(tmp) > 0 then
            tmp := tmp + '-' + format('%.2x', [pIfTable^.ifRow[i].bPhysAddr[j]])
          else
            tmp := tmp + format('%.2x', [pIfTable^.ifRow[i].bPhysAddr[j]]);
        end;

        if Length(tmp) > 0 then
        begin
          AdapterDataFound[m].bPhysAddr := tmp;
        end;
      except
        bResult := False;
        Result := bResult;
        Exit;
      end;
  finally
    if Assigned(pIfTable) then
    begin
      FreeMem(pIfTable, ifTableSize);
    end;

    FreeAndNil(IPMasks);
    FreeAndNil(IPAddresses);
  end;

  Result := bResult;
end;

var
  AdapterData       : TAdapterInfo;
  i                 : integer;
begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    WriteLn('');
    if Get_EthernetAdapterDetail(AdapterData) then
    begin
      for i := 0 to Length(AdapterData) - 1 do
      begin
        WriteLn(Format('0x%8.8x', [AdapterData[i].dwIndex]));
        WriteLn('"' + AdapterData[i].bDescr + '"');
        Write(Format(#9 + 'Link encap: %s ', [Get_if_type(AdapterData[i].dwType)]));

        if Length(AdapterData[i].bPhysAddr) > 0 then
          Write('HWaddr: ' + AdapterData[i].bPhysAddr);

        Write(#13 + #10 + #9 + 'inet addr:' + AdapterData[i].sIpAddress);
        WriteLn(' Mask: ' + AdapterData[i].sIpMask);
        WriteLn(Format(#9 + 'MTU: %d Speed:%.2f Mbps', [AdapterData[i].dwMtu,
          (AdapterData[i].dwSpeed) / 1000 / 1000]));
        Write(#9 + 'Admin status:' + Get_if_admin_status(AdapterData[i].dwAdminStatus));
        WriteLn(' Oper status:' + Get_if_oper_status(AdapterData[i].dwOperStatus));
        WriteLn(#9 + Format('RX packets:%d dropped:%d errors:%d unkown:%d',
          [AdapterData[i].dwInUcastPkts + AdapterData[i].dwInNUcastPkts,
          AdapterData[i].dwInDiscards, AdapterData[i].dwInErrors,
            AdapterData[i].dwInUnknownProtos]));
        WriteLn(#9 + Format('TX packets:%d dropped:%d errors:%d txqueuelen:%d',
          [AdapterData[i].dwOutUcastPkts + AdapterData[i].dwOutNUcastPkts,
          AdapterData[i].dwOutDiscards, AdapterData[i].dwOutErrors,
            AdapterData[i].dwOutQLen]));

        WriteLn('');
      end;
    end
    else
    begin
      WriteLn(#13 + #10 + '*** Error retrieving adapter information');
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

