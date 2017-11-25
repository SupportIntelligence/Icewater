
rule n3e9_2b2a93b9ca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b2a93b9ca200932"
     cluster="n3e9.2b2a93b9ca200932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply grayware malicious"
     md5_hashes="['957855dd87c6e3d1c444739e07584d03','a08c0d3d5c2c8acef7d21c4bc66054f9','d323b2ccfa45563d5a3fa66cb3f76f9a']"

   strings:
      $hex_string = { 0070007500740010004400690076006900730069006f006e0020006200790020007a00650072006f001100520061006e0067006500200063006800650063006b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
