
rule k2318_39124ac9ea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.39124ac9ea210932"
     cluster="k2318.39124ac9ea210932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['6c15fcd36e930508720d3596dc3409be2ca65ef2','4d804f4d14a5386ed2de58a96274b9dc634f0037','301db4b4adca79aafdb4ed757567239982684f0c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.39124ac9ea210932"

   strings:
      $hex_string = { 6d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e50 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
