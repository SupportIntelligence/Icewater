
rule k2321_2b1e5cc9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b1e5cc9cc000932"
     cluster="k2321.2b1e5cc9cc000932"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['96acc0208366b91d48f09e81afe380c5','c493b57d6bcca76d3f6f5cd9e5513e73','d0bd657444c7807ff7f081625fb3fad7']"

   strings:
      $hex_string = { 594c20d7af5235f84f99e8a1aab0ef2a54615740156845265405b9caefa50e2ef310a328845f1b22e9620991174b70ed30a0186eb6cfddd8dfc31e9d41abfbc0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
