
rule n2319_29105c8bc76f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.29105c8bc76f4912"
     cluster="n2319.29105c8bc76f4912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner bitcoinminer coinminer"
     md5_hashes="['e32e935d62a2c46f19c918fe2b715990948b348e','a7b38a94ca84c2d87c002f96e581b5f60a38677d','2cfdfb682eedb2c7dae9e3b381b06ac84487a77c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.29105c8bc76f4912"

   strings:
      $hex_string = { 732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c287029297472797b6966286e7c7c216f2e6d617463682e50534555444f2e746573742871 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
