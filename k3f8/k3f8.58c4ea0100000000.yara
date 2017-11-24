
rule k3f8_58c4ea0100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.58c4ea0100000000"
     cluster="k3f8.58c4ea0100000000"
     cluster_size="35"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit hacktool androidos"
     md5_hashes="['000f0fa06b5d6fee3ec0355c45d971cc','005f7dcbf1fb2482c8831da1f7596730','8a9447cccc79b854d7006ada8002fe64']"

   strings:
      $hex_string = { 0776616c75654f6600067665726966790005777269746500000001010b81800488190d04a019000001010e818004c4190f01dc1900000302108180048c1a0309 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
