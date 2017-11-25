
rule n3f1_4b16a4cbc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b16a4cbc2220b32"
     cluster="n3f1.4b16a4cbc2220b32"
     cluster_size="35"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads androidos andr"
     md5_hashes="['049f3ebaf70df22a738bcc223ea9e54f','07da7f2cf635b9197dbc726bdfcf7b94','822f35192795ded93dd192b343f50052']"

   strings:
      $hex_string = { 530003152c3f4e5d69737b800e22354c7494abbfd1e0edf6fc05234faad3f709266aa7e1fd072571c5f96eb9f5fb9ddbf2286db5e7022e83c7f12a8cdaf82b89 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
