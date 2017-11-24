
rule m3e9_7434c59c16d1cb15
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7434c59c16d1cb15"
     cluster="m3e9.7434c59c16d1cb15"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbinject diple"
     md5_hashes="['09f6504c00b5fd828f00812985fc0c6f','a0ce5fc592795c794525791980f18601','fe0089154f73592cb17b7f93ea1d6325']"

   strings:
      $hex_string = { d6c0693f32322f2e2e2e303e696fbfbfb46d736f5151501211a9daf8f9f9f8f5cd46260000002381818186c5d6d9dbdbf4f2b76a634d4b4142636eb7c1cbcbbf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
