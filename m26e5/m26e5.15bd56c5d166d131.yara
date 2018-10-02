
rule m26e5_15bd56c5d166d131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26e5.15bd56c5d166d131"
     cluster="m26e5.15bd56c5d166d131"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['961ca4c3afbe32bb6f8b18613e101c79cf5808bc','ddb8d472747396e700491cb087ded8e9804accfd','722cce78d81636f61bc30da18a5b33fb6c8ba8ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26e5.15bd56c5d166d131"

   strings:
      $hex_string = { 83f80173398b0e2bd153bbffffff3fc1fa028bc32bc283f80172282bf942c1ff0233c98bc7d1e82bd803c73bdf0f43c83bca0f43d18bce52e8520400005b5f5e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
