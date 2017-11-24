
rule n2321_5996e048c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.5996e048c0000b12"
     cluster="n2321.5996e048c0000b12"
     cluster_size="81"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['02721a61eaa5eb70f62997e301096c5e','05796902954d4dbe0f99c31b96aec0e6','381553f85a35492e53d14d24b868eef8']"

   strings:
      $hex_string = { 66bf73fa01c04255195cb553064ffd159ecb2d679589770d7ab0ba784eb838fb3b8834f9d0356e40e88164594a7e14a752d45654846f1cf6dcb2c76b2a48e6e2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
