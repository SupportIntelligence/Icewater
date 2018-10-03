
rule k2318_3718b5e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3718b5e9ca000b12"
     cluster="k2318.3718b5e9ca000b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['d8e7f05fef722dbd4754f009386827fd1ba46c95','ff782e316d8786290de636f3124d0dc4687e9304','aa02eca2ba1e913c337194bf4665d91e44bb1702']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3718b5e9ca000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
