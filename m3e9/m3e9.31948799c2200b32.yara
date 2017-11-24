
rule m3e9_31948799c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31948799c2200b32"
     cluster="m3e9.31948799c2200b32"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['03fc52542dbc9a42d47b348644504e8f','0e27098db044e7e9f1ada5382f471cbd','a46a0b5231cff55f3685752983a1765f']"

   strings:
      $hex_string = { 938f96a6a5bdc0c1c2c2c5cfdbdedee5def7f7b7000000eefdfd33353c3c3f3f3c4648494f527d7e7d7e838e7c8484919191a3a5a4a8babdc6c5c8d3dddee5ef }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
