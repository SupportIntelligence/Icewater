
rule k2318_351933a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.351933a9c8000932"
     cluster="k2318.351933a9c8000932"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['bcbaf031cb42fa8db342bfe080f8fac3009e3b45','c09915519b6fcb2ddaa2b8afab1181bef746f58d','571a2ad4320d3041d6fadefc31f694ca3f483bba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.351933a9c8000932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
