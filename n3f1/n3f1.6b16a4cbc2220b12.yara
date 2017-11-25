
rule n3f1_6b16a4cbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.6b16a4cbc2220b12"
     cluster="n3f1.6b16a4cbc2220b12"
     cluster_size="4"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos andr axent"
     md5_hashes="['21d564d1aacf496e9bb3b19be8421464','909f0ed53a9d1b0dc2a15d2cee983d40','aac22e7efaeb1475080a817d9dc66058']"

   strings:
      $hex_string = { 530003152c3f4e5d69737b800e22354c7494abbfd1e0edf6fc05234faad3f709266aa7e1fd072571c5f96eb9f5fb9ddbf2286db5e7022e83c7f12a8cdaf82b89 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
