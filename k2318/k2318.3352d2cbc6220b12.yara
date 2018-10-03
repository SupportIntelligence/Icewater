
rule k2318_3352d2cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3352d2cbc6220b12"
     cluster="k2318.3352d2cbc6220b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['2676538a5e9373900a94ab8ed1f55dfe37f63ca2','26a78a6a9d5d4f32ed9f1af9259a542cfdd2707e','c0af068004f00e7679d2e5f2cf81e743d726e178']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3352d2cbc6220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
