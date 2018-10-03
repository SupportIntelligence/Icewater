
rule n26bf_1b9c6a4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.1b9c6a4cc0000b12"
     cluster="n26bf.1b9c6a4cc0000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd malicious kryptik"
     md5_hashes="['8ce372889e2efa9c604cfc858e2b1a56b6506f3a','3d2af669a2ed3b3e180acd0e78547b5cba0e79de','0efb284feb2c1e8f72a1558f3fd81c37927ac93d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.1b9c6a4cc0000b12"

   strings:
      $hex_string = { 2a000000430000004078777b9de7e5f0ffa39db7ff878296ff666276ffb4add6ffa9a2d5ffa09ad6ff908bd9ff837fdbff6b67ddff4e4cdfff302fe0ff1313e2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
