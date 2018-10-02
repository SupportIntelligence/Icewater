
rule n26e5_2936ec29d5a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.2936ec29d5a31912"
     cluster="n26e5.2936ec29d5a31912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['8a0f56c9f40674e7ad79492561d86b29234e053d','a98b156bc954f58677233a3179b341bff14fd11e','2a872fa3c09169cf7d76a4aced894649743e4d2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.2936ec29d5a31912"

   strings:
      $hex_string = { 8bdfeb0b3970188d581874038d581c8d4e1c3bd1894dec0f9445f033c03bd10f95c08d04851800000003c68945f48b38807f2000753eff75f0c647200153c646 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
