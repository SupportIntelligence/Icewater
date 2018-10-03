
rule n26bf_6966586bce630b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.6966586bce630b32"
     cluster="n26bf.6966586bce630b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="passwordstealera malicious quasar"
     md5_hashes="['ddef1c5db050d1a5c8aa432cb1b04a34b808023f','b1902e2fb6a9a3bc92f49736bb9316eb3de652a0','05b6bcff75b1e42572576e353105192061896cba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.6966586bce630b32"

   strings:
      $hex_string = { 022d0b727a040070732a00000a7a0774060000020c080304056f100000060d0916fe0416fe010a07280800000a26de0c11042c071105283f00000adc062a011c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
