
rule k3e9_6ab2d79498cb8912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ab2d79498cb8912"
     cluster="k3e9.6ab2d79498cb8912"
     cluster_size="233"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload hacktool nsis"
     md5_hashes="['00e68ae7f2f3d2993c4fcfa1bd82cdfa','0121467d2d136133a4a44b2d3ba9d675','108068ea082b6e48cf6723c758c39d5f']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
