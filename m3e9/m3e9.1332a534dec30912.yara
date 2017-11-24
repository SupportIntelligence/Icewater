
rule m3e9_1332a534dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1332a534dec30912"
     cluster="m3e9.1332a534dec30912"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi socelars socstealer"
     md5_hashes="['251e88e980d60e9ecd541717133666ed','28103e85bc9a8eb10e2ce903de3e4aeb','e146ce2a352f1427762cf68c4849f92d']"

   strings:
      $hex_string = { 799dd7d95ee7bccf42e5013c4a1499c47cc85d1a0a53da0825fbb5b178a9865c60f5cc7489108528a85c15c155c6fad259b2afa672126775c2541ddfc5ad3462 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
