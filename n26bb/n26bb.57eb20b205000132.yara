
rule n26bb_57eb20b205000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.57eb20b205000132"
     cluster="n26bb.57eb20b205000132"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob virut malicious"
     md5_hashes="['7775eff41b6c94bb6ecf5db4fe3f4dc888770e94','5495563dd9017b5699cb6134e75cb60d11f14ce2','0f714578e0cf1ace637afd8176dcacfcd0fd549c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.57eb20b205000132"

   strings:
      $hex_string = { 558bec53568b750857bf207f000133db2bfe0fb70e0fb70437663bc874106683f830751c51e89bffffff85c0741243464683fb2672dc33c0405f5e5b5dc20400 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
