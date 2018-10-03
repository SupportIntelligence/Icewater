
rule k2318_39197ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.39197ac1c8000932"
     cluster="k2318.39197ac1c8000932"
     cluster_size="428"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['6aa4abe77d314a64b3b4e0c03de2b0de205be22a','113890fd65c0fceeb76335b333f1efbfffccd041','c04cf34ec647c8f550a1dc2aa8cd6b7afccf1745']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.39197ac1c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
