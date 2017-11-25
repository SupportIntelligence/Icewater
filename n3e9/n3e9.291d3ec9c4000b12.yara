
rule n3e9_291d3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291d3ec9c4000b12"
     cluster="n3e9.291d3ec9c4000b12"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['110d65da2651d58571068da91628e9b1','1120e3dc5e1cedccfcadd6d18abb8390','c2d57cbe26881876ed3c3e445a949aa9']"

   strings:
      $hex_string = { 526567436c6f73654b6579000000496d6167654c6973745f41646400000053617665444300004973457175616c4755494400000056617269616e74436c656172 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
