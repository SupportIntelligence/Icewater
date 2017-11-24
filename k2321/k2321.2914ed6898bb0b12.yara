
rule k2321_2914ed6898bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6898bb0b12"
     cluster="k2321.2914ed6898bb0b12"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['08bc63f9c0cc6bc905e5c194331e4397','13b476ec4709f32b8f6af487fefa1c43','f76567d77dd2fd5e35dbd1a7b16c9a9b']"

   strings:
      $hex_string = { 8be5d8d16360de07efbfd7cee7952c169785925d486225c21242b458a4944afcd52a4491607f1df6c40883d6a022bd064bc01ec4a7bc9cec575edc7ef0871f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
