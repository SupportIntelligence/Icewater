
rule k3f7_219310a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.219310a1c2000932"
     cluster="k3f7.219310a1c2000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['678a7e6cf69d4129a987903cc27797d5','75f5fb53a1f97ed22701575bbd09b046','c6c4a5fc26c28f4afb55fa241137b64a']"

   strings:
      $hex_string = { 6155524c28292c63213d3d64293b6361736522646976657273697479223a72657475726e20692e66696c6c54657874286a2835353335362c3537323231292c30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
