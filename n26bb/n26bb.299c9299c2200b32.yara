
rule n26bb_299c9299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.299c9299c2200b32"
     cluster="n26bb.299c9299c2200b32"
     cluster_size="240"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail malicious engine"
     md5_hashes="['253ddd5e3193cf58a5ecb1bf0e37b76891d18845','4e17e7270c5e190cf887be1d6ed1e7a1c452d7f8','35f936f4d8c300d0c04f1c0ed3a3d6062e49fcb0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.299c9299c2200b32"

   strings:
      $hex_string = { d0dcfa7d5f106862540800af91b4a25099ce159586d9e3521e6f8278419a7b2080f9c161d18dbfe54cb2c0e1cadaacd842fdb775b3df6ebea8f64ba8ed05adb5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
