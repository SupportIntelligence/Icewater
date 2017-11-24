
rule m2322_56890024992148b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2322.56890024992148b2"
     cluster="m2322.56890024992148b2"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['9a4417df25f9f093f5b66971687e8334','dd8f082ea0e914e550159045087d0d2c','f9263a572efab3f78d0d98e59073fe32']"

   strings:
      $hex_string = { f4e2413fb3cb79a4543f466e0ed0f1a8abd65532feb89ef7208ad9a3c13f3c6d3509463bd6c8eb7a31df5f4a3f1d95e4cef2b94c03f08c0f6584afc6dada6c06 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
