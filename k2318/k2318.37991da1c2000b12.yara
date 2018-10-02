
rule k2318_37991da1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37991da1c2000b12"
     cluster="k2318.37991da1c2000b12"
     cluster_size="7676"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['b334807d1877de9031f020a5d7cb4847c0c111d1','ae46c1136f98ff61bba5c2a42087c8ebfcc64938','a246be102f7f92f1285f05766e4f0264d98e73df']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37991da1c2000b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
