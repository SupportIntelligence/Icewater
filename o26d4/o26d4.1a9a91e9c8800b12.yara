
rule o26d4_1a9a91e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.1a9a91e9c8800b12"
     cluster="o26d4.1a9a91e9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy neoreklami malicious"
     md5_hashes="['def2da8aa743fbd18af3f9bbfa94efe5909ae6be','7d85b81d0401ab8e564c5917a6e383a6c53985e4','f89bf8b36cf9d2afb0d836acb8c2c1a014f8e75f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.1a9a91e9c8800b12"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
