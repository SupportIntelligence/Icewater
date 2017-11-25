
rule n3e9_161db52fc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.161db52fc6620b14"
     cluster="n3e9.161db52fc6620b14"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="auslogics silentinstaller unwanted"
     md5_hashes="['014c1e81edfc487328112c822079e32c','03b87f348fe8559f95533a8624025ecb','4e8b15f5ebec671f812a3956efa47364']"

   strings:
      $hex_string = { 74ab66f9f119649b75b015c633d7dd34cae08cb211de08dbc11c58a93c0527c65e7962fbe9131f7ebdfbe1d8fe470fc357612b788f32859c87a3bf149f7c6900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
