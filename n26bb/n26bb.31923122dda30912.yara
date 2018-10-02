
rule n26bb_31923122dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.31923122dda30912"
     cluster="n26bb.31923122dda30912"
     cluster_size="262"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor nymaim malicious"
     md5_hashes="['0e3b75e9aa9d59ec5bc918ad08771ab503c74dfe','e53b1681511e14e430510a5ece222c91e04f1851','b6d4a09d4797917effef5a592b1efe3fd0d32d7e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.31923122dda30912"

   strings:
      $hex_string = { fe7b2160574961049856119140ee90356d6a2ba2c6f3f9734b7dc2c83c3a0678750847eddd0b93e4b286d27123b7426810e9a7fdc1dbe7bb0af4972eaa4819ab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
