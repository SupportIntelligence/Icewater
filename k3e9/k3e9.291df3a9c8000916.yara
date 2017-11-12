import "hash"

rule k3e9_291df3a9c8000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291df3a9c8000916"
     cluster="k3e9.291df3a9c8000916"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['17b7fefe6ffd5b3919a725a443ca7433','6e84d22cd787b3386b631379f741c9ca','e16dd346c0b623874f96908655cf7dd6']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

