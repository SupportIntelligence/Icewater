
rule k2318_3713212eae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713212eae210b12"
     cluster="k2318.3713212eae210b12"
     cluster_size="731"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['23d54e6fde991cef8fcf1c3a88e35e707107ca8e','97affcf7c9ffce5e589c2de7255201abd7ded991','44067f74bc724a63b0cc2d7291d663fc3ab12cc9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713212eae210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
