
rule k3e9_63b4b363d8a69b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d8a69b16"
     cluster="k3e9.63b4b363d8a69b16"
     cluster_size="212"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0163a4b28d299ed457146111e6db9087','024cef328d3c511cf7f3162e1ded3f0c','199283875abb099dd8492fc5067856fc']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba1a08700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff158410 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
