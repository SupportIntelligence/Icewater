
rule m3ed_10daeda9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.10daeda9c2000912"
     cluster="m3ed.10daeda9c2000912"
     cluster_size="8"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['07f06e541e80c07824902becbc131a8e','15df4110f633817ae04406548d093f3a','dfb8998f993bf21eac2d812a11c0c1df']"

   strings:
      $hex_string = { 44000000f531fc311632de33eb33f93329346434a134ab34c334ec3420354f35303784373d3855385a38c33ae33a323b653baa3bb73bca3b923cb83db13efa3e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
