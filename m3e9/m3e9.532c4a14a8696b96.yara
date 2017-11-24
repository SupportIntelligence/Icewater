
rule m3e9_532c4a14a8696b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.532c4a14a8696b96"
     cluster="m3e9.532c4a14a8696b96"
     cluster_size="71"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['012f5be65a85e739438d6bfcdf092d0c','0377c5b4c7acadde79303eb3e0d07910','3d64e518de7579dcbecadbcd04dab121']"

   strings:
      $hex_string = { e524d60d1d03adbb54e3dcdf4cd9b160c9cddeb018dbd592115f752e167331f3f48293780be420708a63fbd3c33ac27cee640c9998aabc0a6fc633f761894dea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
