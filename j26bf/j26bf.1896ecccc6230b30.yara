
rule j26bf_1896ecccc6230b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.1896ecccc6230b30"
     cluster="j26bf.1896ecccc6230b30"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo genx malicious"
     md5_hashes="['258e782a4a50677497ce4be9d52b90923fd1b59c','e5d4750bfdb3d8ed10905db2b46025d4f882b40f','0aa6c27cf91d906ada88f8e89a76cf3683422655']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.1896ecccc6230b30"

   strings:
      $hex_string = { 756c740044656661756c740073656e646572006500646973706f73696e670076616c75650053797374656d2e5265666c656374696f6e00417373656d626c7954 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
