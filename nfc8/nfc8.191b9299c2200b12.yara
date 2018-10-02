
rule nfc8_191b9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.191b9299c2200b12"
     cluster="nfc8.191b9299c2200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="aiodownloader androidos crepmalware"
     md5_hashes="['17120283cb99c53af104a6121f351ce77f73d9fe','4044649c1f4ced1d5920b310128885943844757a','72968a14a000c22626470ee3a87ee08211d4c652']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.191b9299c2200b12"

   strings:
      $hex_string = { 4374524e536600b24f1b412efdbc6a9cf8d78378fa09e5c8b8b5afa9a47c0af4f2d394918a6d605f5a48eedcac8f7f7572c48e7bfcebdfd0a087f1ece1dad5c1 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
