
rule i445_0bb9c13401001122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0bb9c13401001122"
     cluster="i445.0bb9c13401001122"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot winlnk runner"
     md5_hashes="['15fcadb435aea0f23e305bb3d0f400df','685b8f1f584ca990d4d7de0b2736db51','cc64b79c61b07fbbccbb9bb208900fb6']"

   strings:
      $hex_string = { 00000000000000000000000000002500770069006e0064006900720025005c00730079007300740065006d00330032005c0063006d0064002e00650078006500 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
