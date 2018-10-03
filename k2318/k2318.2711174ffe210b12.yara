
rule k2318_2711174ffe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2711174ffe210b12"
     cluster="k2318.2711174ffe210b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['67aac4c8127dd4d50a65753d2f073ca105b06edc','8a19eb04841a79aa614639625a62a80a696c5ca3','07bd34ada6fe679cbf3ef8aaee2d41da19489916']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2711174ffe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
