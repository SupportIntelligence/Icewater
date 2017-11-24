
rule i3ed_051b4681ce2c9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.051b4681ce2c9932"
     cluster="i3ed.051b4681ce2c9932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue symmi accv"
     md5_hashes="['039c5aa8edc042d2c0ea8f3db9c80b4e','2cad6de8d50f64e2537dfe6774876127','a4433e2348e84182580d8bc4ddcb2cd3']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a15030001083ee04ebea50ff151020001083255030001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
