
rule nfc8_231d34e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.231d34e1c2000b12"
     cluster="nfc8.231d34e1c2000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos revo"
     md5_hashes="['01ebe5b7fac9d7ccecd709f524bffb1e04fa0df1','89985a8992fa7fc197f6e834185da8bb2d6b0c2b','cc9e4f953dd972ad2218cb085d7d5ee592c6a00e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.231d34e1c2000b12"

   strings:
      $hex_string = { ba290c769131f85c2870b80a83d541b274332e8a8736b72d86f2e7513ad6edd2e3731b66c6b62792da018dd899b37a0d60f49b9d5b6732dfe5f6597d8b785e4b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
