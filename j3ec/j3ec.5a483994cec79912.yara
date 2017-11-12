
rule j3ec_5a483994cec79912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.5a483994cec79912"
     cluster="j3ec.5a483994cec79912"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="crytex hublo geksone"
     md5_hashes="['206c1739d2c750c59a22743f33452dc6','478ea66039e65fe7e557b084de9b869a','f2976dd9edfaee2bd09e2637a3bc6dde']"

   strings:
      $hex_string = { 62675072696e74000062004e74436c6f736500bf004e744f70656e46696c6500006d0252746c496e6974556e69636f6465537472696e6700006e74646c6c2e64 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
