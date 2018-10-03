
rule k2319_39156902d7ab0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39156902d7ab0932"
     cluster="k2319.39156902d7ab0932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script loic flooder"
     md5_hashes="['038ad5b69bf25483bf16c93b1d76589f770133fe','1357034398efb04b11a2e4aed7f3fe9d2d2d0a09','4ad1cfe99a93dc29d1cd104eabfbd4632a0c3b42']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39156902d7ab0932"

   strings:
      $hex_string = { 30535531464239734c46774d65436a6a68634f4d414141442b5355524256446a4c745a537654674e424549652f5752526e6d3355385243316e655164736d317a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
