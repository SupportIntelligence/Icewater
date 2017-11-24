
rule k2321_2115ecedb24448ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2115ecedb24448ba"
     cluster="k2321.2115ecedb24448ba"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['35e9785fa9fd5017272d58d339522449','63cca38ba12777c3e1842d512e905b68','c7099a8551c38d4c40d58e2b47d2dc74']"

   strings:
      $hex_string = { 3f3726b876e874bd0d554b29cacd1f573473c850ee3e844fdc95654145fd36de3c72a0ea8b778d9f6c2b7fad8a982a5cabc2bcba55e012f2da8cf87e40d3c946 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
