
rule n26d7_534d5111999fb9b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.534d5111999fb9b3"
     cluster="n26d7.534d5111999fb9b3"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['f2fbd2dc9ef34af47f0f3978f32547abc5bf3777','2098899b65cb1a4c88626534ab60aa8d12d0aec9','f45718ee9177a62ba95543246210571da79598c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.534d5111999fb9b3"

   strings:
      $hex_string = { 72f53bc1750d83f9407308896c8424ff4424203bea76028bd533db85ff0f9cc38d4424188d6a014b23d833c03bf87e2bb8d34d6210f7eec1fa068bc2c1e81f03 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
