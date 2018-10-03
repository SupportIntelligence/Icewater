
rule k2318_211b96c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.211b96c9c8000932"
     cluster="k2318.211b96c9c8000932"
     cluster_size="51"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['85cc68766e4397face67e806f759a8c729b838c7','5e01f82bdd3a719a344c13cd8600af326bd62681','77d38fce7136c3f57109dfe0395948cef5ed066b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.211b96c9c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
