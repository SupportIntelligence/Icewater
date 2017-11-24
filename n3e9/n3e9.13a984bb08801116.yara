
rule n3e9_13a984bb08801116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a984bb08801116"
     cluster="n3e9.13a984bb08801116"
     cluster_size="182"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun zepfod"
     md5_hashes="['040e0aba0fd25d456e64be2bd99e8f48','05e1198a1938fb75685331ab5b75be20','2c2fa1633cee0c232ce6832c7275475f']"

   strings:
      $hex_string = { 0025a2abe1ff5778e2534b42f7481ad454360edaf2c2e4eeb985fbc42b5ccbf0f9dc0ca9ebb322f66151cd24c8fc47de8133d419d7957367825097b7725f0d20 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
