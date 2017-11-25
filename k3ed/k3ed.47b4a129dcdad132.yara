
rule k3ed_47b4a129dcdad132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.47b4a129dcdad132"
     cluster="k3ed.47b4a129dcdad132"
     cluster_size="8484"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox ocna yontoo"
     md5_hashes="['0003a6fd455b8acfee2dbfd403cf7f80','001551dceea7e0d1ecdbe9d4938e6bdf','00c1d8f6bf0f706610c956cd46cff6d2']"

   strings:
      $hex_string = { 450833d25356578b483c03c80fb741140fb7590683c01803c185db741b8b7d0c8b700c3bfe72098b480803ce3bf9720a4283c0283bd372e833c05f5e5b5dc3cc }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
