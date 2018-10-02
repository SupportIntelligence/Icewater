
rule k2318_33193da1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33193da1c2000b12"
     cluster="k2318.33193da1c2000b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['9854bd40936005faedeaf95bdb2e3c735564c9d8','3a74cccd33a0105d3a9c1191f43f86b23654c148','08c6b3fc6ee8717c31c8deeed7b1f6cedb6a8990']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33193da1c2000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
