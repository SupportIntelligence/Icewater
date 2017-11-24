
rule m3e9_5c14696ad1b2e332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c14696ad1b2e332"
     cluster="m3e9.5c14696ad1b2e332"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky jorik"
     md5_hashes="['03d8a3adfc9e4b0554ad70eb7e035082','0f3eafe634b31e48caae74bc2c7a52a3','ead0ec3a63573023f3d902b6b2f11f7b']"

   strings:
      $hex_string = { b9d8dbd9ccc3c0b77cae969d98021279d8f3f6f3f6ddce4a220000000c2e2e2b53c0ccccdbf3dddb3d0a290a292a2e2f4277b6d9ccbebd7a7daf96999910076a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
