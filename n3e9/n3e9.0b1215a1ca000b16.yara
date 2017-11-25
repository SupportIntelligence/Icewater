
rule n3e9_0b1215a1ca000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b1215a1ca000b16"
     cluster="n3e9.0b1215a1ca000b16"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler riskware"
     md5_hashes="['05a4d977e272637071ce47952daa5da2','0eb2ceca3624c5d81092db94d9aa7c9a','a50ef4909742ce5a359bdec071aaf959']"

   strings:
      $hex_string = { 70007500740010004400690076006900730069006f006e0020006200790020007a00650072006f001100520061006e0067006500200063006800650063006b00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
