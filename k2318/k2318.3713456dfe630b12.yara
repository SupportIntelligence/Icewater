
rule k2318_3713456dfe630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713456dfe630b12"
     cluster="k2318.3713456dfe630b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['d13a92415cfafeef5aba9598e88cba54bce19038','7ed9711f65a6eb96ff1fe284e32051f1188a0cfa','010d843e00e6133a0e57f09a437a91d1f849f925']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713456dfe630b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
