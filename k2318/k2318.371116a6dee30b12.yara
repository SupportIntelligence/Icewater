
rule k2318_371116a6dee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371116a6dee30b12"
     cluster="k2318.371116a6dee30b12"
     cluster_size="159"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['dccd2cb082252fa81aa1ae80aac5aeef702ac372','2ddea1326d09978a934950adf66f6f624ccb3df8','1ea492294b19674fc40a8d5f896a5fa4d0f8835f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371116a6dee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
