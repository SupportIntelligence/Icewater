
rule k2319_690f3949c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690f3949c8000912"
     cluster="k2319.690f3949c8000912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['20808eb113dafb37858965a487d44d4cb6e13477','fd5e8e594b9f452561f0585bb526ef91a7ef709f','54d8d9019cbd5e7e4e3301eaac8fed6ab4f59771']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690f3949c8000912"

   strings:
      $hex_string = { 44333d66756e6374696f6e2862297b76617220423d27223b7d273b76617220643d273d22273b76617220653d2835302e3c3d28307842382c332e36354532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
