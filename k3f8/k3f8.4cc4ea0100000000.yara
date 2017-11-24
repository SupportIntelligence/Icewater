
rule k3f8_4cc4ea0100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.4cc4ea0100000000"
     cluster="k3f8.4cc4ea0100000000"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit hacktool androidos"
     md5_hashes="['a7d9708937db69d681912f49cc25adfa','a9722a7d1c0640bf6efbcbf9672ba8d2','d7fdabbeba5ea0868da24e60f9842b7c']"

   strings:
      $hex_string = { 0776616c75654f6600067665726966790005777269746500000001010b81800488190d04a019000001010e818004c4190f01dc1900000302108180048c1a0309 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
