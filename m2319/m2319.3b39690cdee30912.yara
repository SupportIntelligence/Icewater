
rule m2319_3b39690cdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b39690cdee30912"
     cluster="m2319.3b39690cdee30912"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['77c7bff914c996b58ebe0ae9f542635d2103fa7f','3b8ef5b4cabab870d0966aee168705c23fae0bf6','cf81ff23e4c47b4e2b5c8bba2b3330fd6ecacbe6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3b39690cdee30912"

   strings:
      $hex_string = { 346e2b312927292e637373287b636c6561723a2027626f7468277d293b0a20202f2f202428272e626c6f636b2d677269642e666976652d75703e6c693a6e7468 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
