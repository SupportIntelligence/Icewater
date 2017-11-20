
rule m2321_33944ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.33944ab9c9800b16"
     cluster="m2321.33944ab9c9800b16"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['3c32e6cc32425c95df8a5c6d040b9700','438d93c22b9175f9f56bc5a5972e8c2b','d8907d00410bd894d273aca7e1f48ac1']"

   strings:
      $hex_string = { c92f977e6ac4fef6dd7716cdafcfca181911128c991f9b2968e5efa5004f304418e8eb4d6f2a050686040620fc375fa954575ebcb8ba72e9dc1a1c0bab2baa8a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
