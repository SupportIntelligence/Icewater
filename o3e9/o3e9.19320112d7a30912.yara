
rule o3e9_19320112d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19320112d7a30912"
     cluster="o3e9.19320112d7a30912"
     cluster_size="27"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy noobyprotect unwanted"
     md5_hashes="['00daa0900c9d6f5d36c356f0b80315b8','194105e0f23f0b8d1e7172c40a1ed9bc','9ce3ccb852b3b3460ab5bc31d4e5f286']"

   strings:
      $hex_string = { 3b9dbfebf98599ba201cd3a414714903d1a05cb4ded4df0af2e916e07d6be6f88d684d2e3d3631269e1ad000b64e78ff286ee20554a150ec3ae790d5703ed684 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
