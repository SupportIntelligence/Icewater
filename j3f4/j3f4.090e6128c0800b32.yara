
rule j3f4_090e6128c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.090e6128c0800b32"
     cluster="j3f4.090e6128c0800b32"
     cluster_size="104"
     filetype = "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy agbf malicious"
     md5_hashes="['006a50cb2766485b04252fcd6536bb0b','02e80f85fa13ac11516f245348845d77','1fbffdc6ffd6961b6a2392c1057d4417']"

   strings:
      $hex_string = { 00000000000000000000000088e3f2ffb4f7fbffb0f5f9ffaaf1f7ffe8fafcff56bdd4ff68b9cdff70c9e0ff90e2f0ff89deeeff82daecff6fcce2ff68c6dd96 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
