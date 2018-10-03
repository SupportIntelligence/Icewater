
rule k2318_7990d6b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.7990d6b9ca800932"
     cluster="k2318.7990d6b9ca800932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['fc47aa26d0130bcfec1dc32f4a183531eb3567f7','55166bba0d74a22124ec9d7716e672286daf017a','5bd114dc5cdd131786d629eba30e0e61a7646c5f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.7990d6b9ca800932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
