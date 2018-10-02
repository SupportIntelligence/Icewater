
rule k26d7_259e4acc9ee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d7.259e4acc9ee30b32"
     cluster="k26d7.259e4acc9ee30b32"
     cluster_size="108"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="veil malicious skypespam"
     md5_hashes="['839910dfba2bf532c89d1c032bc8503a679267c5','1260daf708d6517bbf3e6c3bdc00501b1be93dd8','57530edd0f212ef7fa1dc9e8375cc6098eaec28c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d7.259e4acc9ee30b32"

   strings:
      $hex_string = { e70809c289e883c0018944241089f8c1e80b0faf44240839c2729c8d5c1b0129c729c221f181fbff000000769a8b6c2410e945fdffff9083c41831c05b5e5f5d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
