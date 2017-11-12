
rule n3e9_019c1dc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.019c1dc9cc000b12"
     cluster="n3e9.019c1dc9cc000b12"
     cluster_size="2613"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt diple"
     md5_hashes="['005134da642652ee7a2d976b52d81c86','00f996bcfd9cc93c79153f48238257dd','04573ec151456e3c7d9983cd68805415']"

   strings:
      $hex_string = { 57e928aaa2e5febff44e8f7e790324083cff00e86eac62d2d2963fefcff8f47d39c614c8ad1a690d2a321562fa4ae4923d11dcff009c3ef47b9e44519d74ff00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
