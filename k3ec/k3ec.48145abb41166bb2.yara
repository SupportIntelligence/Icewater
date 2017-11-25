
rule k3ec_48145abb41166bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.48145abb41166bb2"
     cluster="k3ec.48145abb41166bb2"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['38b291cf13ff68a13f1eed8bd9151037','c3c56d7233b7b74611d123030ec56509','db25b3e8df0cca4016c09ed494ddf963']"

   strings:
      $hex_string = { 312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c212d2d20436f7079726967687420286329204d6963 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
