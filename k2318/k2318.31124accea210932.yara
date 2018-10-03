
rule k2318_31124accea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.31124accea210932"
     cluster="k2318.31124accea210932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['62373481c4f473e09c35fce8af3cb2988289ee19','76c9e8b3ee542b4798be4bb3d2538b0a0e8118b3','edc5d65742b63d78c88d1993a74fcadc5e84f19b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.31124accea210932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
