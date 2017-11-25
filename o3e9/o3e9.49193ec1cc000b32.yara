
rule o3e9_49193ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49193ec1cc000b32"
     cluster="o3e9.49193ec1cc000b32"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur malicious"
     md5_hashes="['7f7fbfbd8d8a6b8a3f2bc5d1bd754750','a8065160559ed210434a8b9726feb191','cf1455c78f31b57ee16bfab005a0b7d2']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
