
rule k3e9_092b311e4b8a8912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e4b8a8912"
     cluster="k3e9.092b311e4b8a8912"
     cluster_size="112"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag adload"
     md5_hashes="['009cefb91f050d5191eab81a331f43bb','010e5549fc22b96c1227fc77bbc26814','2c37e31416cfc27770f581a6ff063d89']"

   strings:
      $hex_string = { 83c41085db750431c0eb290fb74358807c305c00741383c4fc6a005650e833ffffff8b00eb058d76008b0689038b4308010389d88d65e85b5ec9c389f65589e5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
