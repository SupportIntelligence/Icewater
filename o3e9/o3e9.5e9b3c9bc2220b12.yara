
rule o3e9_5e9b3c9bc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5e9b3c9bc2220b12"
     cluster="o3e9.5e9b3c9bc2220b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur cryptor"
     md5_hashes="['1535fb88a49419c8ee7a63f1b5f7dca7','25a7817d83f375d79a46562098726194','b8fb1ad212cbb0675fe4032fe5d0af5c']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
