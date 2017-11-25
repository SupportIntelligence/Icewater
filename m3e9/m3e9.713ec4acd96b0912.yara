
rule m3e9_713ec4acd96b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.713ec4acd96b0912"
     cluster="m3e9.713ec4acd96b0912"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys wbna"
     md5_hashes="['1bc12993af7228a02eb1046124265b6e','3126680047c229e2204614f4b6e1b177','ebcc7d70233e41f20b275af6e3ea19bc']"

   strings:
      $hex_string = { 642e5c8abda3c34769472a33a4a6cfa6a776755d684f3103ebf0ea097badb09cb5b4b4721e51305a0000000062414b4366445288a2be7638382f4e3c2a89a3bf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
