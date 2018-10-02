
rule pfc8_393433a0daeb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.393433a0daeb0932"
     cluster="pfc8.393433a0daeb0932"
     cluster_size="80"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fwefw highconfidence jiagu"
     md5_hashes="['74f13af94f9164e727539de2e4e3f83692f944b1','0f4a127ee348183ef31774c3ff5dde8d052abc64','9439a52c6a4794f5917f7086a72cb6baa02af264']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.393433a0daeb0932"

   strings:
      $hex_string = { bb1f692b6d9f6e8df4cd441b8272a53b360ff3d7fd8019e55d1464c1a6d5d873eac631067cc2ce3578ef5e26a25fcc15371ce0f857246734de5154ca3e752f33 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
