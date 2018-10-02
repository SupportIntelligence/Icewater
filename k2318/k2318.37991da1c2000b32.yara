
rule k2318_37991da1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37991da1c2000b32"
     cluster="k2318.37991da1c2000b32"
     cluster_size="5139"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['1d59c67d5656037574a53d374a0370d3acd65983','d1d17e2515f4375b58417c78df1df494171319a7','d373c8fb7d3440878dd7151fd5f674333a49d910']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37991da1c2000b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
