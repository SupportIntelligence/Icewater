
rule k2319_491e1ce9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.491e1ce9c8800932"
     cluster="k2319.491e1ce9c8800932"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem expkit script"
     md5_hashes="['8586872fbaeabaa525a60fb0ec230cd9780dc802','c912d3be0285a896b959b8ccfad0394b99097a5e','f2ff503e700b80850202f9a78788f5877d9b6900']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.491e1ce9c8800932"

   strings:
      $hex_string = { 32492e4639493b7d2c65373a66756e6374696f6e284e2c512c74297b76617220793d22773249222c473d282831302e363945322c3131332e293c3133383f2835 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
