
rule n3f1_129b3ac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.129b3ac1cc000b32"
     cluster="n3f1.129b3ac1cc000b32"
     cluster_size="33"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakeinst androidos opfake"
     md5_hashes="['081af82129c662a7b694183a25dd26a4','0b99afdac2bdbb35b146ffa3b30e2c9d','7f2c87880bab7d6478fdee8ea7591003']"

   strings:
      $hex_string = { baee9847ca1cbea6af8bf23907641acc338da1c3b70954122995e76b566127c54083f4b5bff717ff05b3fe08fd90dd215cc0a84c5587b6a73db47dbbb89c2ea5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
