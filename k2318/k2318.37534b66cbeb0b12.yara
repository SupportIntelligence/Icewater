
rule k2318_37534b66cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37534b66cbeb0b12"
     cluster="k2318.37534b66cbeb0b12"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['7b32fa522c3b4d1ac7ca3b7cbbfc24b46dcee81c','0a30130c0c903fbca43cdef8ed310bfa63e2a460','4ec5813e5d42c00aad5dd656317e87841c79763a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37534b66cbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
