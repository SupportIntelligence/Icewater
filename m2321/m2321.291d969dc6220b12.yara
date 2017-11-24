
rule m2321_291d969dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291d969dc6220b12"
     cluster="m2321.291d969dc6220b12"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['16f4879dc5d42050a6951d4f1199aea3','1d6893cfeda739edecd7ef907132de27','f61b667a7f6c1f0ea0bd66d57e36d147']"

   strings:
      $hex_string = { 496eeab67744ee947f4ba50bc089a1a47ba25e1e6def75a9728a80967e8d97c8f22f25e85ce94174a0d0cf079ad338ff1234e71254355064e4c39c16b12cbbed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
