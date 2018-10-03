
rule k2318_311915a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311915a1c2000b32"
     cluster="k2318.311915a1c2000b32"
     cluster_size="313"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['37f6dd1b4f57bf859a1fd0e74ca9dd3b41ec6e04','2ca0486f6b0a3b46dae669986b94cd19bf6300c4','a8d76d56102d667b0b508210f7617a0907725b3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311915a1c2000b32"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
