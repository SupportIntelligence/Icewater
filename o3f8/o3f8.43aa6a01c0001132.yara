
rule o3f8_43aa6a01c0001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.43aa6a01c0001132"
     cluster="o3f8.43aa6a01c0001132"
     cluster_size="278"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smsthief andr"
     md5_hashes="['8c29fc01046e4ca3afb91920967010ed0bbd0cc7','d0f108b999b466aa6c8e8c0356a4da366841f488','9c1b2fa2a3e26cfecb1197b547238d502275f6b2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.43aa6a01c0001132"

   strings:
      $hex_string = { 094b45595f5449544c4500074b53433536303100184b65794576656e74206d6179206e6f74206265206e756c6c00084b6579776f72647300014c00054c415247 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
