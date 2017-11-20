
rule m2377_5a9a3949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5a9a3949c8000b32"
     cluster="m2377.5a9a3949c8000b32"
     cluster_size="91"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['02f105815edd47134e90b68ddd26bef7','03d2677b2456c619f0ac5565637d7cbf','2a2579d2ed60a16532b10ece046a2384']"

   strings:
      $hex_string = { ccd2ac6b89861e42d74eb73bc91fb238bdbe9e92637c6c1ce81de396c078cd1a19d8b941f9f097c7a5e404a3d6ca4a66775cf8df5621720339980c5f1bd9de13 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
