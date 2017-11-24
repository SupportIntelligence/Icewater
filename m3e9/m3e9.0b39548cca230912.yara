
rule m3e9_0b39548cca230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b39548cca230912"
     cluster="m3e9.0b39548cca230912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00b42a82755b96b6350be6f465c1822b','1fd0667cfa242ac56bd9766e43310d68','d353419d87f333a2ee6f7c909162092f']"

   strings:
      $hex_string = { 92233bd6ad682fbd15f7626e9438060d9ee2b27d0b8be94504cf1266d58c6478722b91e41a4703bc938777d20e978ad0f3392ad129e15c730fb8f407429c63a6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
