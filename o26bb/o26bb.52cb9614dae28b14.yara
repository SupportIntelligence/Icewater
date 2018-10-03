
rule o26bb_52cb9614dae28b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.52cb9614dae28b14"
     cluster="o26bb.52cb9614dae28b14"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious kryptik"
     md5_hashes="['d362872880f62dfad37039b80a59e4b5c0b783b8','ea8f83819e32dc36860936acf5d90559c674c873','3a66242cd2def237cb33910a8b7914004d8da01b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.52cb9614dae28b14"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
