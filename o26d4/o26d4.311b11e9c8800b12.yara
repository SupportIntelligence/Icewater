
rule o26d4_311b11e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.311b11e9c8800b12"
     cluster="o26d4.311b11e9c8800b12"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy neoreklami malicious"
     md5_hashes="['61d5ad11dce9c2ff35c50176bc5d7898f8ef6b9a','2a81690b43a2803ac3d6cc41329023c8090de2a5','fc8f373e96a9761d79310ac4f7eae54ef14ddf69']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.311b11e9c8800b12"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
