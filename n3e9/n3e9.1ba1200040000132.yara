
rule n3e9_1ba1200040000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba1200040000132"
     cluster="n3e9.1ba1200040000132"
     cluster_size="1136"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack jadtre"
     md5_hashes="['0144fc856300ea8574fade2eb67edb32','020fe4bc8b7c797603f1464c56e28584','067530e7e4af1bf43aeb57876d039119']"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
