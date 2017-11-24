
rule i3ed_1672c4cdc6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.1672c4cdc6210b32"
     cluster="i3ed.1672c4cdc6210b32"
     cluster_size="13"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="padodor backdoor symmi"
     md5_hashes="['11ecd55492c6ccc3c9d69b9324bab030','16d02875d5b8020c9a5d0d7fd9f8b8b8','ff6ad26841b5d1e5ea828d7b2e135323']"

   strings:
      $hex_string = { 59c9bc6da58c3d5775928def57334f14fee454a189ecbbd8b810db835dac3f88e5d83223d79ce9f8b0a453b16a292dca4e287917be1d5311584312a89bd45681 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
