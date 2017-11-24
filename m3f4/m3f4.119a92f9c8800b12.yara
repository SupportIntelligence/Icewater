
rule m3f4_119a92f9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.119a92f9c8800b12"
     cluster="m3f4.119a92f9c8800b12"
     cluster_size="306"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy amonetize advml"
     md5_hashes="['0309947f30d9241e5208471158896118','0358a90df803a7d4327efa2b97ff2fb4','14cb0e01cd7d0c31537995b07a7f0254']"

   strings:
      $hex_string = { 6c676f43686f72642e4167656e74496e7374616c6c65722e50726f70657274696573004147454e545f52454749535452595f4b4559004d595f4441494c595f56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
