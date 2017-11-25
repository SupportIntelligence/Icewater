
rule n3f1_4b14a48bc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b14a48bc2220b32"
     cluster="n3f1.4b14a48bc2220b32"
     cluster_size="23"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads androidos andr"
     md5_hashes="['13a4ed15b998ffb315cc87db002c5610','1f12efb1c6c48ed0ce95865e552fab2b','cc22ad74dccb36e055a06ab8ce70ebf0']"

   strings:
      $hex_string = { 530003152c3f4e5d69737b800e22354c7494abbfd1e0edf6fc05234faad3f709266aa7e1fd072571c5f96eb9f5fb9ddbf2286db5e7022e83c7f12a8cdaf82b89 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
