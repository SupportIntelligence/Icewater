
rule o3f8_6a1fa154c6830b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.6a1fa154c6830b12"
     cluster="o3f8.6a1fa154c6830b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos apprisk clicker"
     md5_hashes="['cfb53768fd931951e9558261614f37625c652416','cc4b237a1f2f858051c469d8b9b3d8e131644ccb','d7a037814b7764ffea2daadb83c97c92d2f447d2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.6a1fa154c6830b12"

   strings:
      $hex_string = { 0040c0800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
