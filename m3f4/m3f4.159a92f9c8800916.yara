
rule m3f4_159a92f9c8800916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.159a92f9c8800916"
     cluster="m3f4.159a92f9c8800916"
     cluster_size="53"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy amonetize advml"
     md5_hashes="['082b13a0e0183516280d587ab7f4d611','09f079f5b9ce7a1c88755f1cb544f75e','57ab8a0a4754995ba6f34e6a903c828e']"

   strings:
      $hex_string = { 6c676f43686f72642e4167656e74496e7374616c6c65722e50726f70657274696573004147454e545f52454749535452595f4b4559004d595f4441494c595f56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
