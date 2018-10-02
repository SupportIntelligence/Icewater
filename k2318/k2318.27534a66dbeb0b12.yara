
rule k2318_27534a66dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534a66dbeb0b12"
     cluster="k2318.27534a66dbeb0b12"
     cluster_size="387"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['5e2255b68f0a4d40848ab578207c4ed546799bd4','901adf296fd9adb9378a7d4974ff378543ee43f7','bc31028581cb6b266b5038e0c920951e5f2484d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534a66dbeb0b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
