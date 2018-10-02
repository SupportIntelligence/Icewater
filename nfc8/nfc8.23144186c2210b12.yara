
rule nfc8_23144186c2210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.23144186c2210b12"
     cluster="nfc8.23144186c2210b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos revo"
     md5_hashes="['f95ed4f6244ecf4f716a4d7e86d8ba5d4d1bbedc','9199089fc1b6f7aff9b2a4cd4a9a1d8c43c19225','89360373d1fdf726d44200ee2ea633279891c376']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.23144186c2210b12"

   strings:
      $hex_string = { d765c0fb679acb7f70e9a4992366fd752f7a6305124422724f89427db7ce0bf0539ca56c844698b0aba0a2b5976f1e5cd2264b4cda78410a024d2c6e934ea750 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
