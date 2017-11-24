
rule m2377_6135a008d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.6135a008d9bb0932"
     cluster="m2377.6135a008d9bb0932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['32d4ffa94a80734070e946313dc35dc0','3e804d6bea27de2a9ad67f1910441d25','739ada8189078b18269c5e2819be00b8']"

   strings:
      $hex_string = { 654f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
