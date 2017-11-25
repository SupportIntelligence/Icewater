
rule m3e9_3a5fb04bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5fb04bc2220b14"
     cluster="m3e9.3a5fb04bc2220b14"
     cluster_size="69"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['3625b1cf5b0743b5326b6a54d2c04630','43cd1ad1e8180343483ab20a29dc582b','a301d5fec936464ef6d5aaa42be3f443']"

   strings:
      $hex_string = { 4190c20ba21dc6d607c325fe2edff4298131b8198bd23976d909138c486c1eb19fddea86d7f89e3e8350823f5f51a9b712688a3c4e606fac98e1cb04552d15e8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
