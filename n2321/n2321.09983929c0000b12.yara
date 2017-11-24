
rule n2321_09983929c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.09983929c0000b12"
     cluster="n2321.09983929c0000b12"
     cluster_size="29"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide bundler downloaderguide"
     md5_hashes="['00c6689ad534f634a56a92910a44d32d','05507274910907f075029b199dac8f88','930fa4b9ab43c1091c50de9603c4c732']"

   strings:
      $hex_string = { 976703f78b7a78d1bec5bc1abfb48487dbfdf099518a0290235e9a34aa2128360761014570244b39158e4c2ae6600eeb53b944c6de4f487f0add6fd835e77642 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
