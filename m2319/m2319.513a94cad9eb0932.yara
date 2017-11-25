
rule m2319_513a94cad9eb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.513a94cad9eb0932"
     cluster="m2319.513a94cad9eb0932"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script injector nemucod"
     md5_hashes="['23d33ddcde08e22e412d834507c80931','95985c3045dfc3bfd599dceb546666bd','fb3da1bb6ede66bba49ca792470c369d']"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
