
rule k3f8_0000000058c4ea01
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.0000000058c4ea01"
     cluster="k3f8.0000000058c4ea01"
     cluster_size="12"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit androidos hacktool"
     md5_hashes="['005f7dcbf1fb2482c8831da1f7596730','454f58e8f1a22b96ae508097b43e58bc','f253101f66b5c00b3a73a0f83d1002f2']"

   strings:
      $hex_string = { 0776616c75654f6600067665726966790005777269746500000001010b81800488190d04a019000001010e818004c4190f01dc1900000302108180048c1a0309 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
