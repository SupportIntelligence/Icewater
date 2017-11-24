
rule n2321_091c909dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.091c909dc6220b12"
     cluster="n2321.091c909dc6220b12"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal wapomi"
     md5_hashes="['04e86c067dce4e63b0ac706497b3c31c','3233af2463bd4917d4694e82dfc6b1c2','f5de6815fa37250b144bc593f05ad182']"

   strings:
      $hex_string = { bf736a12a8ab1f7528a6d77405fa77341cf4b4d807dbe5f6e270bcee093c3631f0c90c52b24de64e6d140aef995ea525d2f78d1d3be413b01be90b3ec7ede390 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
