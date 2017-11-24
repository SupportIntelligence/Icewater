
rule n2321_0ac322a569955666
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.0ac322a569955666"
     cluster="n2321.0ac322a569955666"
     cluster_size="253"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00488e9705b957eca6ffef0f2df593f0','004f49e239e8d34491f3306af73ce79f','0e925e796b343895739ea2badfd6052c']"

   strings:
      $hex_string = { b82215cf60f21c2558d37efdaedd97358dcac11a0572296e14eb0f515c6386d0a2d267239aecfcd7edc82f8576d46af818a481ba047f00b0c29d96073912dc69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
