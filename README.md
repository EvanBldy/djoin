# Offline Domain Join Metadata File Decoder

Offline domain join is a process that joins computers running Windows® 7/Windows Server 2008 R2 and later to a domain in Active Directory Domain Services (AD DS)—without any network connectivity. This process includes a new command-line tool, Djoin.exe, which you can use to complete an offline domain join.

Run Djoin.exe to provision the computer account metadata. When you run the provisioning command, the computer account metadata is created in a .txt file that you specify as part of the command. After you run the provisioning command, you can either run Djoin.exe again to request the computer account metadata and insert it into the Windows directory of the destination computer.

More information on Offline Domain Join can be found at: https://technet.microsoft.com/en-us/library/offline-domain-join-djoin-step-by-step(v=ws.10).aspx

# Project
This is a fork of @bradleykite sources who can be found here : https://github.com/bradleykite/djoin.

The project of @comaeio helps me too, it can be found here : https://github.com/comaeio/dinfo#offline-domain-join-metadata-file-decoder

It works on debian.

## Requirements
To compile that project you need two libraries : uuid and openssl.
To add them install packages below by typing that in the command prompts :
```bash
  apt install uuid-dev libssl-dev 
```

You also need make and gcc : 
```bash
  apt install gcc make
```

## Compilation
To compile you only have to type in the project folder:
```bash
  make djoin
```

Next run :
```bash
  ./djoin filename
```

To clean up the project :
```bash
  make clean
```

# djoin.exe metadata format

Run Djoin.exe to provision the computer account metadata. When you run the provisioning command, the computer account metadata is created in a .txt file that you specify as part of the command. After you run the provisioning command, you can either run Djoin.exe again to request the computer account metadata and insert it into the Windows directory of the destination computer.

These computer account metadata files are composed of a base64 string. This decoded base64 string is a DATA_BLOB encrypted by NetpEncodeProvisioningBlob / NetpDecodeProvisioningBlob private APIs from netjoin.dll which is new toWindows 7/Windows Server 2008 R2. Both functions calls NdrMesTypeDecode2 / NdrMesTypeEncode2 from RPCRT4.dll to perferm the encryption/decryption process.

Decoded blob file contains a structure which is composed of information about Domain Dns Policy, Domain Controller, miscelleneous information about the machine and so on.

# Results 

```bash
./djoin djoin-sample.txt
        Domain Info Version: 1 (0xcccccccc00081001)
        Size: 3a8 bytes

        Machine Information:
                Domain: ad.yalemu.fr
                Computer Name: testyalemu
                Computer Password: mZPf:TVv?REPP<;'Io-@5awA*R+MdStv:6f&+%dVQ2t&n'fUs27G3(gW)hD[I?\@qg_OH(fM`K;2P:r[K=2&Ir+95 ^Se';<nv>[&N*:K8qQi:r+j3yAvHHV

        Domain Policy Information:
                Domain Name: AD
                DNS Name: ad.yalemu.fr
                Forest Name: ad.yalemu.fr
                Domain GUID: f106154f-d6ca-8348-8c7f-af10e39afc44
                SID: S-1-5-21--1601293236-400107208-1135612523

        Domain Controller Information:
                Domain Controller Name: \\srvads-temp.ad.yalemu.fr
                Domain Controller Address: \\192.168.154.204
                Domain Controller Address Type: 0x1
                Domain GUID: f106154f-d6ca-8348-8c7f-af10e39afc44
                Domain DNS Name: ad.yalemu.fr
                Domain Forest Name: ad.yalemu.fr
                Flags: 0xe00013fd
                Domain Site Name: Default-First-Site-Name
                Computer Site Name: Default-First-Site-Name

        Options: 0x0
```
