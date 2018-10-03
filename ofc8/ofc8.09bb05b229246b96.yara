
rule ofc8_09bb05b229246b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.09bb05b229246b96"
     cluster="ofc8.09bb05b229246b96"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['220c817493b2019eadbdc887dc0bb24fef6b26e1','0aeaa4f821213390c546730c72d552c4a1c4f0b1','d8f23381094ebbae0bdca6d7fd5da6bb34a0094d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.09bb05b229246b96"

   strings:
      $hex_string = { d302b95b64201ddacc87e6c2b0048d67f574d29b5c12d1474f11d65f06fd92eb3ca875e8d8db778baab205dd1e4600e4ba359c8907509ab391a33bdf6c1ac4f0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
