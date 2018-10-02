
rule n26bb_299e92b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.299e92b9c2200b12"
     cluster="n26bb.299e92b9c2200b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail malicious download"
     md5_hashes="['91955d362b12fa31992af13b137eada8c41a5aaa','d0e90bd08ab696ecb70ce3eaed0b02010bc1dac8','c61ca8a16afc11077c542872a1b5fae363ee14e9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.299e92b9c2200b12"

   strings:
      $hex_string = { d0dcfa7d5f106862540800af91b4a25099ce159586d9e3521e6f8278419a7b2080f9c161d18dbfe54cb2c0e1cadaacd842fdb775b3df6ebea8f64ba8ed05adb5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
