
rule k2318_3719b5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3719b5a1c2000b32"
     cluster="k2318.3719b5a1c2000b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['d69d0bdce341d9131d22e3d18451d5debfd0113a','ad03d029686e0048ba3068918f8085182fda212b','958570ef5c4349449fab27ad1d2bef41213cc7ce']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3719b5a1c2000b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
