
rule m3e9_3392ae5c995f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3392ae5c995f4912"
     cluster="m3e9.3392ae5c995f4912"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['0e4ada270941ff9f76471f3872e0d9cf','8a144d1c14d3d26ddb5bd92b2bc66023','f4f263003df93e9ada1e2f493838a1cd']"

   strings:
      $hex_string = { 88ab7ab94da32b7eacdbc8ed753ce4dba4a723d4a9fdc3356646739044ff9f7f2431767b058d1100aaec6819f436ba2ec6efe386bbe7b05b91d0bc3a2a4729e1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
