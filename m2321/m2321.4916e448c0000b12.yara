
rule m2321_4916e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4916e448c0000b12"
     cluster="m2321.4916e448c0000b12"
     cluster_size="33"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00151c158c4ad10b96d55654a867d097','0836f946313b3688cef46230366f3004','7e7befe81aeb2aea9fc0ad20187e7d25']"

   strings:
      $hex_string = { 510edc2d23f7163573f8f469a88a205ffe85a3c421f98cc3e614d1874ea5a40b17e90c18bb0e406b286aaec70d3f5d3b08dd33b6446497395eb70a65134802e3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
