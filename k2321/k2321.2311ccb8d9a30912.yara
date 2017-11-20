
rule k2321_2311ccb8d9a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2311ccb8d9a30912"
     cluster="k2321.2311ccb8d9a30912"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi swisyn abzf"
     md5_hashes="['28ec2a43ec1cb426c8c92c89e1c32c98','4bf48240c41e263cbc6a1d2ac46d244f','fd5da12a5a1453493b9225f4647abcc5']"

   strings:
      $hex_string = { 30b6bc3c5fc2274f724501ffcd9d65158ca185e942df35cf31b3fedcf9519ee2bb6f15766661eb93be2ed624d5c5109ab0f2bab88962ab681c527c1fe4f11b20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
