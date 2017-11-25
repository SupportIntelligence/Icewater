
rule k3f7_692985472ea46bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.692985472ea46bb2"
     cluster="k3f7.692985472ea46bb2"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['0bedd4d34d3b9d1b9fb9f826bf1ed273','24c547f18a9b0b32b009385f4acecfbb','e0ab1d27d19c46d22953cde65056f99f']"

   strings:
      $hex_string = { 6155524c28292c63213d3d64293b6361736522646976657273697479223a72657475726e20692e66696c6c54657874286a2835353335362c3537323231292c30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
