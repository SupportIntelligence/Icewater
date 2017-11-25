
rule n3e9_529993e9c8801912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.529993e9c8801912"
     cluster="n3e9.529993e9c8801912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['4c5e4ea44a966738f52c8cbe08d220d5','66a1d57ba022fe7ffb2e21f075b53e1b','a895c1f326378c3bdcd22cb7bbd9cbfb']"

   strings:
      $hex_string = { 0070007500740010004400690076006900730069006f006e0020006200790020007a00650072006f001100520061006e0067006500200063006800650063006b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
