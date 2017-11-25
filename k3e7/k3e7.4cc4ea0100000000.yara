
rule k3e7_4cc4ea0100000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.4cc4ea0100000000"
     cluster="k3e7.4cc4ea0100000000"
     cluster_size="9"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit androidos hacktool"
     md5_hashes="['24188ed65cf6bedcf6654156e7c98a13','56d00deaadc0c1da048fd85e111fbcbc','d9a1680a474c65cb5fc6d31abbf0f26e']"

   strings:
      $hex_string = { 0776616c75654f6600067665726966790005777269746500000001010b81800488190d04a019000001010e818004c4190f01dc1900000302108180048c1a0309 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
