
rule k2318_3112521b96c30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3112521b96c30932"
     cluster="k2318.3112521b96c30932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['07fae57951fbd52fe78b9c40b34f21e3450bb787','e0f949e3f56dce5996a0cc56d1ab7af79596518b','0c386007ba4c4b9aafc8e2538376bbac56a8e4cc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3112521b96c30932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
