
rule m3e9_611896cfc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611896cfc6620b12"
     cluster="m3e9.611896cfc6620b12"
     cluster_size="1038"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['00869380ffef7e167f167f6292117725','00d066ef96475386c25a806c159f4f23','0f9aa7590fb3a38c9e6f8e399bc8c49f']"

   strings:
      $hex_string = { 523bd61c6a4d3bfbf0e39febf9021237b2617f0fa19d201ec53d81be12f1c323f976345f850dbbf8f2a424e3d230cfbfc9ce3370fff86bb38d2564786ebf2613 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
