
rule k3e9_4c9c824ec5a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4c9c824ec5a30b12"
     cluster="k3e9.4c9c824ec5a30b12"
     cluster_size="548"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna vobfus chinky"
     md5_hashes="['0113fddcdfe9f8e181d526fe341a5e12','025853a478423b9c4c2dfda75dff4e04','1352cd56167f14656fbb9b9d0f589685']"

   strings:
      $hex_string = { 0000000010008008043cf7940800d00194080034005e08000c007118f7043cf75a6c18f7cc1c70060064f500000000f502000000043cf7fe8e01000000100080 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
