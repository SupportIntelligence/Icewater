
rule o3e9_709b3ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.709b3ec9c4000b32"
     cluster="o3e9.709b3ec9c4000b32"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur virransom"
     md5_hashes="['0bbf6e233d35ee133ec84d620254fdfb','af83f39838b4f0317fd2a8e3ce925102','e928497417e30b467273c0aad935cda1']"

   strings:
      $hex_string = { 009b360900824914002659200039330d00432b070051544b003e6f6c000c1a0e000a090600231b0a003b350b004a2302004f240200604015007d7149009c3d0d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
