
rule o231d_131299e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.131299e9c8800b32"
     cluster="o231d.131299e9c8800b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware androidos"
     md5_hashes="['430e6badcff00429e827cf6eacde4a8d196cb9f0','b27d6cc4c95d7fd823dfc233dc12fb3da7226d5c','83eb1996a6ac17250169f02370ac523706765266']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.131299e9c8800b32"

   strings:
      $hex_string = { 6633bb38c6151ef29e1fc42b230f284c45ead086be8c6412f358c5014ef184f7442cabd64942364a528b8ef46334b359cb412e719bd7fc245a90ba2203b92947 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
