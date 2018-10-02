
rule o26bb_111a90b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.111a90b9c8800b12"
     cluster="o26bb.111a90b9c8800b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ezxank malicious dangerousobject"
     md5_hashes="['3c81875abb78a9ce0f099015cd5c762ea6e936a3','f4524e3f7d5f041d6c5388bb8469a54bf8b46248','9713a5fb455f27b56cfff1e96cfa614bd643ef8b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.111a90b9c8800b12"

   strings:
      $hex_string = { c046fa7884d3285b08641c307e05c209a155beac53c8e79eb701ad24e510e3ec47e131a90a7c8965a5ee262241c100d196d518576ac999bad7bb2195b1777fc5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
