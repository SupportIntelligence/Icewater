
rule m3e9_61360c86b13b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61360c86b13b0912"
     cluster="m3e9.61360c86b13b0912"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['13dd02de591e3ad8063d0f5a6e7b0253','2977b5bc931ad5fa4b1912f3ba163ea3','f3082e3b9f61a4493ceab6faf4c25eec']"

   strings:
      $hex_string = { 16fef1923b5511353aec0dda8477dcfaca1836874ba2a1cf5eba6d23a34197e56c8a6e2520768c138e1f7b5848a779c4bd0bf627d746b3f817519603f4c549eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
