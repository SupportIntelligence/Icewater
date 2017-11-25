
rule n3e9_3b1e7a49c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1e7a49c4000b12"
     cluster="n3e9.3b1e7a49c4000b12"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious applicunwnt"
     md5_hashes="['01d56c01781005ed6b9816398bf575a5','26c00da6c01f2133477ab7f2ce34d129','ec12cc2849a410d10c138b04fdf3673e']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
