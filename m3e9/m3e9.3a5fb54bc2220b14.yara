
rule m3e9_3a5fb54bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5fb54bc2220b14"
     cluster="m3e9.3a5fb54bc2220b14"
     cluster_size="280"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['00f23f2179a3516a6fa0874f43e72e49','0abe3cb77a0706d54ba7894f2d5bfb7e','32c92e4980a1ce136c323e9a1b4de8cb']"

   strings:
      $hex_string = { 4190c20ba21dc6d607c325fe2edff4298131b8198bd23976d909138c486c1eb19fddea86d7f89e3e8350823f5f51a9b712688a3c4e606fac98e1cb04552d15e8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
