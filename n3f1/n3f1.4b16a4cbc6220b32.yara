
rule n3f1_4b16a4cbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b16a4cbc6220b32"
     cluster="n3f1.4b16a4cbc6220b32"
     cluster_size="131"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos boogr andr"
     md5_hashes="['028c9aa3d9039c405bff4876d1a4d27b','054bfaa0efb9c8f2cd8cf3d022b3e511','14aec431989ec66fd506a9eff7b12d2c']"

   strings:
      $hex_string = { 530003152c3f4e5d69737b800e22354c7494abbfd1e0edf6fc05234faad3f709266aa7e1fd072571c5f96eb9f5fb9ddbf2286db5e7022e83c7f12a8cdaf82b89 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
