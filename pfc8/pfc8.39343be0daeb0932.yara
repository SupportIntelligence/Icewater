
rule pfc8_39343be0daeb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.39343be0daeb0932"
     cluster="pfc8.39343be0daeb0932"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos jiagu apprisk"
     md5_hashes="['90d70517f6345b5cb045d3ee9b707e8342f6c499','bd6e8087d81f5b946394f497af1c1ea23dedaf1a','f55d6d2a3b9cb9bdff053967a56d7fb0dcc2ba39']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.39343be0daeb0932"

   strings:
      $hex_string = { bb1f692b6d9f6e8df4cd441b8272a53b360ff3d7fd8019e55d1464c1a6d5d873eac631067cc2ce3578ef5e26a25fcc15371ce0f857246734de5154ca3e752f33 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
