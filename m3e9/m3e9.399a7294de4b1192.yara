
rule m3e9_399a7294de4b1192
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.399a7294de4b1192"
     cluster="m3e9.399a7294de4b1192"
     cluster_size="56749"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator rstdbjki gain"
     md5_hashes="['0001f0c1ff2343e93d995feef0213973','000927ce1cb65558d671fdff4a1c40bc','00341465633d9280f33b8e8b35242840']"

   strings:
      $hex_string = { 33db833d24ec4200017e0c6a0456e8e61f00005959eb0ba118ea42008a047083e00485c0740d8d049b8d5c46d00fb63747ebcf83fd2d8bc37502f7d85f5e5d5b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
