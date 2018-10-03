
rule n26bb_319215e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.319215e9c8800b12"
     cluster="n26bb.319215e9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious bscope"
     md5_hashes="['2d849486fbd0989a3f6bf81bab4219067423fb2c','652c3de59ff8de6fa80005b02a805e1eb2e13b33','7205150c9331a90284225b93ed81a60455e20068']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.319215e9c8800b12"

   strings:
      $hex_string = { c5663975087403017dfc8b732885f68b45fc894320743e807e4100750d8b4df056e82ce4ffff84c074628a46410fb755f80fb6c803ca3bcf7e07017df48365f8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
