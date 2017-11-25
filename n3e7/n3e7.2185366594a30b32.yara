
rule n3e7_2185366594a30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.2185366594a30b32"
     cluster="n3e7.2185366594a30b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor speedingupmypc malicious"
     md5_hashes="['697ca6f02b4292c11d1a8d571ea9acd9','7c76fb64e4f5d236b13d420267cfdef0','cf0a0bb22aa36a890c9464b574c83923']"

   strings:
      $hex_string = { 45295dc11087c3a9a84bfd238698bee9dffeee265263317a354d70b2c8507b191749ce5609b8fa65d0d6a593996232ea4a6457d895c6063f41bf2d0e676fb6ab }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
