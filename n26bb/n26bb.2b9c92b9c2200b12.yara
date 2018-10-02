
rule n26bb_2b9c92b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b9c92b9c2200b12"
     cluster="n26bb.2b9c92b9c2200b12"
     cluster_size="47"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious engine heuristic"
     md5_hashes="['7cda65e2676123a4e0dea80a1eb4bdbbeda225ff','08a6592f942f550dbac6bd8cda6471e53c6186eb','778c0f25ae23119c1c2a792e89369f415399e015']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b9c92b9c2200b12"

   strings:
      $hex_string = { d0dcfa7d5f106862540800af91b4a25099ce159586d9e3521e6f8278419a7b2080f9c161d18dbfe54cb2c0e1cadaacd842fdb775b3df6ebea8f64ba8ed05adb5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
