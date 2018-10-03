
rule n26d7_429ca852d9f2d992
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.429ca852d9f2d992"
     cluster="n26d7.429ca852d9f2d992"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['dec315120c7cca4dc17bdb0230f4c1720294c34e','27391acbb2a7d6528ad50007f3993d966bc8717c','a3854ea3dc19a7035e729e6b1b0c6d94fc619367']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.429ca852d9f2d992"

   strings:
      $hex_string = { 72f53bc1750d83f9407308896c8424ff4424203bea76028bd533db85ff0f9cc38d4424188d6a014b23d833c03bf87e2bb8d34d6210f7eec1fa068bc2c1e81f03 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
