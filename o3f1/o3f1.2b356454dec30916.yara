
rule o3f1_2b356454dec30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.2b356454dec30916"
     cluster="o3f1.2b356454dec30916"
     cluster_size="60"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos risktool skymobi"
     md5_hashes="['08fda2b10d47d7c87528b7fd62fc9085','0aabba19f8b6d81c09014bd0f680ad31','48c27e2e3fd9e10786d98c55227900e6']"

   strings:
      $hex_string = { 167a7b1ba68ebc2a695228f224978513a29fdb58ae1c9abd36da6b5706238d9ecff90af509f1956287dc51e0c88ff6e5c6e9bea0f4e2a42c44081894d315ee14 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
