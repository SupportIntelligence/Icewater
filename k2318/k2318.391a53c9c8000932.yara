
rule k2318_391a53c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.391a53c9c8000932"
     cluster="k2318.391a53c9c8000932"
     cluster_size="108"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['704a7b0a1519e57f1a157d61919bc2d4f9eb4a70','cec30ba736b287760c0535070ab7a09af91dcad5','d5aaba28535c4102a0c81fd3e2254b02c3fc0bd8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.391a53c9c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
