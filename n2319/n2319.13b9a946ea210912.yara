
rule n2319_13b9a946ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13b9a946ea210912"
     cluster="n2319.13b9a946ea210912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer cryxos"
     md5_hashes="['ce8db59645ff9afed4e6cd739eb768c185306477','138cbb3cd32ca5b943ecec4131c94278136ceacc','d5e856fae86f24cf0c902e5a514e0786626c9fcd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13b9a946ea210912"

   strings:
      $hex_string = { 5d2c2131292e6c656e6774687d7d293b76617220792c7a3d612e646f63756d656e742c413d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c2328 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
