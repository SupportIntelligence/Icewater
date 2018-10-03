
rule k2318_3112d38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3112d38bc6220b32"
     cluster="k2318.3112d38bc6220b32"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['6c19d32d3bd241f8ee2af2291a6b072d7874c866','3abfc6890fe935d5afef4cd4635a9a0f0d84c296','94891e9540f3d6a8f56262e665618f5d086a0bde']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3112d38bc6220b32"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
