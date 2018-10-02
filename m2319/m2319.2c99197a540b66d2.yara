
rule m2319_2c99197a540b66d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2c99197a540b66d2"
     cluster="m2319.2c99197a540b66d2"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script clicker"
     md5_hashes="['4361d1e6041cc0945c293c58bce152b1f267d716','7201ac82761f1b8ba001d83e7c137a988aaff93b','3d60b997dd2bea77fcede99d7a7a4066420510a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2c99197a540b66d2"

   strings:
      $hex_string = { 64676574206279207777772e62657374346861636b2e636f6d2623383231323b2d2a2f0a2e6c6162656c2d73697a657b0a6d617267696e3a3020327078203670 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
