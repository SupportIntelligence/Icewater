
rule n3f8_1194f0c1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.1194f0c1c8000b12"
     cluster="n3f8.1194f0c1c8000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot banker androidos"
     md5_hashes="['358213b84986bf156d7ede09b0c350fef07a95a4','eacfd3eac77791c3c45b4edae8fc6acea9d75477','889f76ae3a0ce461bdf39e5f88e4f66ba866c894']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.1194f0c1c8000b12"

   strings:
      $hex_string = { 797374656d3b00154c6a6176612f6c616e672f5468726f7761626c653b00294c6a6176612f6c616e672f556e737570706f727465644f7065726174696f6e4578 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
