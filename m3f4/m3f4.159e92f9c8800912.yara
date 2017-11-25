
rule m3f4_159e92f9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.159e92f9c8800912"
     cluster="m3f4.159e92f9c8800912"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy amonetize advml"
     md5_hashes="['10b0811b1c5a2fe9c32f8495dd9caca1','15aae55068c1937ab120aa4560db1c0b','9e064e9e3b7909e5faff57a0473b83ca']"

   strings:
      $hex_string = { 6c676f43686f72642e4167656e74496e7374616c6c65722e50726f70657274696573004147454e545f52454749535452595f4b4559004d595f4441494c595f56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
