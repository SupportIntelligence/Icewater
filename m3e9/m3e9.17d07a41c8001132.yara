
rule m3e9_17d07a41c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.17d07a41c8001132"
     cluster="m3e9.17d07a41c8001132"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre ipatre kryptik"
     md5_hashes="['029fef2843168eceee815329f949db67','038bde9ca0db2ea836380f45b8a8894e','7dc48d8590c11479e39dca4f9cf32189']"

   strings:
      $hex_string = { 000083c0088945f4eb03895df4395df40f843d01000057ff75f4ff7514ff75106a01ff7520ffd685c00f84e20000008b3520a04000535357ff75f4ff750cff75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
