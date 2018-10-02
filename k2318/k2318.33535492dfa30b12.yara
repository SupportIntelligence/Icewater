
rule k2318_33535492dfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33535492dfa30b12"
     cluster="k2318.33535492dfa30b12"
     cluster_size="102"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['d5eb3633d8a2b757a8d6ba6e08ad9d03171ffb7d','4a56cb0e5a2b1ec8e12c5d0fa0b5ad39bb653074','a5c42a1f6e3f0ff376e622463b41b888aa011da3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33535492dfa30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
