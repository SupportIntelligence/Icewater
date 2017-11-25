
rule n3e9_291d3a49c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291d3a49c4000b32"
     cluster="n3e9.291d3a49c4000b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious bmfoq"
     md5_hashes="['04601566b598bb8a7117de6e9d339d2f','21c5ccb1498dea139f2c8244d1e8fc00','aafc53ffb1e943e2ccb25bfef2349cb9']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f41646400000053617665444300004973457175616c47554944 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
