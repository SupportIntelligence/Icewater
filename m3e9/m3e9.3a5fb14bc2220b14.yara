
rule m3e9_3a5fb14bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5fb14bc2220b14"
     cluster="m3e9.3a5fb14bc2220b14"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['42173a29325f0a77aa4a6c0c2d160ff4','45412cbf25a81dd8fff4b2fc34bac654','c8b5550d8f5e9563ff07c290e0c3c555']"

   strings:
      $hex_string = { 4190c20ba21dc6d607c325fe2edff4298131b8198bd23976d909138c486c1eb19fddea86d7f89e3e8350823f5f51a9b712688a3c4e606fac98e1cb04552d15e8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
