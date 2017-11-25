
rule k3f7_239994c1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.239994c1c4000b12"
     cluster="k3f7.239994c1c4000b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['1a252d8bd0bec148615610e822b02a20','27bfafc9d459d40cab2df68f1e60848e','e966f551042910c33ad23ea948cc42de']"

   strings:
      $hex_string = { 6155524c28292c63213d3d64293b6361736522646976657273697479223a72657475726e20692e66696c6c54657874286a2835353335362c3537323231292c30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
