
rule k2318_391933a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.391933a9c8000932"
     cluster="k2318.391933a9c8000932"
     cluster_size="104"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['5ba1ec5cc0b122d2c031529536ca254d032e2815','c12b5bc352ce82a4702e535f0ea01ba8e4e96def','2d479b087f1eba581a440ac468d8e412d3b41818']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.391933a9c8000932"

   strings:
      $hex_string = { 6d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e50 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
