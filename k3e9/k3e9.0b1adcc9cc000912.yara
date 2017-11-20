
rule k3e9_0b1adcc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b1adcc9cc000912"
     cluster="k3e9.0b1adcc9cc000912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0277eddb2c1af474cd8e95cecc682158','1801d3af18c8f5653e09c6bebc578bad','edd3e53e2cd8cd7aab6c4a5852af1eea']"

   strings:
      $hex_string = { 594c20d7af5235f84f99e8a1aab0ef2a54615740156845265405b9caefa50e2ef310a328845f1b22e9620991174b70ed30a0186eb6cfddd8dfc31e9d41abfbc0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
