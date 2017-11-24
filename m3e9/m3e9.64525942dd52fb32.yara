
rule m3e9_64525942dd52fb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.64525942dd52fb32"
     cluster="m3e9.64525942dd52fb32"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik emailworm"
     md5_hashes="['0249e848ee0b8108d78ab0bc8fe9027a','3d9f1fbc2a7942077c538f657ce73f5a','e3f37300ee36f12b393c2ddb069cbffb']"

   strings:
      $hex_string = { 65736c30586d5b5759719a9e9cc0ceccaea9aae6f2fafdfdfdfcfcfbf7b7000000f7fdfd05161f1a1818181a275c678687877878d9f4d6abc9cdced7d7caafae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
