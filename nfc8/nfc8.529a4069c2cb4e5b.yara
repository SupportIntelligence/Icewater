
rule nfc8_529a4069c2cb4e5b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.529a4069c2cb4e5b"
     cluster="nfc8.529a4069c2cb4e5b"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos koler boogr"
     md5_hashes="['436a80ce9413d125c63576b7988af02b30b9e37a','a85f4cfc3f3d7927a51a5f7aa3cb5ae0837bc241','b118d50c15a631a3330360331fe8ae408635dc46']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.529a4069c2cb4e5b"

   strings:
      $hex_string = { ba68d65db153ca288517428000e8d7676dbcf0e26450d4f7c073ce33ec41e57bc8ab209203c4079339efcdc5ad77dc8e65cb7e434922e19b2990b09801dbb67d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
