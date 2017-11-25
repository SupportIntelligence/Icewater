
rule m3e9_3a55c2e4ef408b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a55c2e4ef408b14"
     cluster="m3e9.3a55c2e4ef408b14"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['1d3180310477a916b0c4aca2430755f8','3881ccfb06ea44032d6f4fe03b658afc','eb27bdc352a001b83effa5592535e94c']"

   strings:
      $hex_string = { 8d396036f232c39b04fd64f9cbe1270bb58412e25add6d9b869400ff423d7c51967bd6c00eb4774d2a5911f0b20272f16241d15ac24c7f8c1d58cf739ffc6395 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
