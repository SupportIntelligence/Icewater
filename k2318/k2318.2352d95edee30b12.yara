
rule k2318_2352d95edee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2352d95edee30b12"
     cluster="k2318.2352d95edee30b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['fcd9132897b923478a81e937da9426e33e6ef767','3a1f494938a590e8e24164dae34a06dce67c5dfb','36a6ed0db5fe538def03fc63d84d3e5655a2ea52']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2352d95edee30b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
