
rule k2318_211a934bc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.211a934bc6220932"
     cluster="k2318.211a934bc6220932"
     cluster_size="98"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['65aaef7575b00527ed9baa2ff5c6daf75a200836','8c4c4603d043086c7177e5993c89bdca21fa1cc0','eb2e8cf4f32b83083308d6292141eb91b5dd2ffd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.211a934bc6220932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
