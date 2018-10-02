
rule m26bb_26665934dbd2cf95
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.26665934dbd2cf95"
     cluster="m26bb.26665934dbd2cf95"
     cluster_size="525"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adposhel malicious agen"
     md5_hashes="['892544149519114c0824150df91fd69e66dd6d9d','f4269773ba070187b9453ef742c80eff66024a04','fcc6cb427ef267ef0df83d091bf759b1c1aadb2e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.26665934dbd2cf95"

   strings:
      $hex_string = { 7f66bf2018c003585f1e8e1abb724cf1703a4e54a2cd59f983e1cf90301c6a3ed92caa4ac4eef40b3842ea36de1fe79fbd2e99482fd7d13fd83b325c17ed3494 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
