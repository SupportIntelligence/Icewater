
rule k2321_09695822d5bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09695822d5bb1912"
     cluster="k2321.09695822d5bb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus wbna"
     md5_hashes="['50a758b49c751e389e2d8d20e5dcae3d','572d0ea8703a4d94679af17b1a2a760f','b436883eacaf4b4117f19f8f5bcc05c6']"

   strings:
      $hex_string = { 41a82eb72918f73ff66dc371645a0dd3018c0f16759c9bdc8bee46cabc4d850bd1e7b09e9e89e3799a61ae8afce568d431d649869d57c5b56094d65b232ba5aa }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
