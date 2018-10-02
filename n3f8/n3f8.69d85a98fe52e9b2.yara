
rule n3f8_69d85a98fe52e9b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.69d85a98fe52e9b2"
     cluster="n3f8.69d85a98fe52e9b2"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos apprisk feeaqu"
     md5_hashes="['5e8902848dd92fa0b38421a7ad052adb5c33b97e','749e3ad997d38a24c6e7305489c8b56aba990c2f','ab9bc1ce1426d8f2a2c0ad18831522967945d82d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.69d85a98fe52e9b2"

   strings:
      $hex_string = { 682b6c3866394736545131704e440a6463774143734472566a4650616230772b4e316a6565762f6b2b626435594c784561513348745a766d674f58424c2b6b52 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
