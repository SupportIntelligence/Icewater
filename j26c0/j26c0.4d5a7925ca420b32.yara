
rule j26c0_4d5a7925ca420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26c0.4d5a7925ca420b32"
     cluster="j26c0.4d5a7925ca420b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob malicious virut"
     md5_hashes="['9296c872be2d1925b72c78af45369bfbda8fcd9c','f977365615215afb19f4fa1cddcb0418948656f0','70529b2f59cd18cee5e4e1e8d2a9c5d42a3f1757']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26c0.4d5a7925ca420b32"

   strings:
      $hex_string = { 436f72652d537973496e666f2d4c312d312d302e646c6c00001306e3776ef2e277a0efe277000000009d6bce0d4067ce0d00000000e1e1f56f273ef76fcf61fa }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
