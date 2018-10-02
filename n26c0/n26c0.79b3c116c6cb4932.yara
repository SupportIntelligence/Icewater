
rule n26c0_79b3c116c6cb4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b3c116c6cb4932"
     cluster="n26c0.79b3c116c6cb4932"
     cluster_size="493"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner malicious"
     md5_hashes="['46c473bacdf4fbd83f884c6f0e9fd774f5cd3493','58f156f06cb1779cb8ece91b4388e8cab623d3d9','d2102933521869b95907cf839f92ff9c1b64a2ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b3c116c6cb4932"

   strings:
      $hex_string = { 8a044d39294a0088068d46015f5e5b8be55dc3b85917b7d1f7e78bca8bd7c1e90d69c110270000894d0c2bd0b81f85eb518955f0f7e18bc2c1e8056bc8648945 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
