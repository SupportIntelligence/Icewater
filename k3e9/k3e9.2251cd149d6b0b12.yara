
rule k3e9_2251cd149d6b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2251cd149d6b0b12"
     cluster="k3e9.2251cd149d6b0b12"
     cluster_size="257"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot wemosis zusy"
     md5_hashes="['0069a8f66da19f81a12745dbec013135','00baff8b39a9590161338d4f9a79a741','1043a0fcad87b08b97e5aee20acd39fa']"

   strings:
      $hex_string = { 5b9e249e1652e0b7e863870520904683568c34880d42e4e7b123820429903a61195efab213be1eb08bc02275105ac99d8bc049da60eb8773c37bb30772f296fe }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
