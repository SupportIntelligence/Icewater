
rule m3e9_13b96b45334d6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b45334d6b16"
     cluster="m3e9.13b96b45334d6b16"
     cluster_size="416"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="honret shipup gepys"
     md5_hashes="['00a183bf2fbf37bba30dfc3eaee78e4a','00d0959a27cd493e5bd1145374b2992e','1a468b24f039e22370f5aad72d86be44']"

   strings:
      $hex_string = { b7fe64c0625e9e480fc3ef547a7614fbbfac5b09cc16326d55071ee3a0939043027f1a702a77dfc7c224c204d0231ce951e695d49d7cbc10974257b24672cacf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
