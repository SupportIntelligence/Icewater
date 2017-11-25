
rule n3e9_3b1d3ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1d3ac1c4000b12"
     cluster="n3e9.3b1d3ac1c4000b12"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply generickd malicious"
     md5_hashes="['0084f01042aa614c64871232308e804d','083e09992907413e64fa11bd330ade03','64603188cb285ac168bdf9e7bf4b4eee']"

   strings:
      $hex_string = { 4578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f707900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
