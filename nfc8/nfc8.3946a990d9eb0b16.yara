
rule nfc8_3946a990d9eb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.3946a990d9eb0b16"
     cluster="nfc8.3946a990d9eb0b16"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="svpeng slocker koler"
     md5_hashes="['947e98010cc3dc0724cbf7c827e2e5428cf2913d','b1ba1575ed6e06d2f30f1bc07e3028f5de26464f','02890d0a890f10392b3787dc439eebdc85681ec6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.3946a990d9eb0b16"

   strings:
      $hex_string = { 15c54b0dbebc9ccadd018046add0d6cb260e16002807d1368a2efcbd7fbd736d046b501d420890ee09ec3f31a22dede61cdafe4d618b7ca1f5a9191394fb84b0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
