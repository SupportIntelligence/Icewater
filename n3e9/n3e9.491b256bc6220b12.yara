
rule n3e9_491b256bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.491b256bc6220b12"
     cluster="n3e9.491b256bc6220b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loadmoney cobra cryptor"
     md5_hashes="['1d89ef32c3fc3862b0938e80cb46c77a','6b5b4b3366d0a0e7417dc4b21aeee806','f76f8440579bb163af85d7c6ce2605f1']"

   strings:
      $hex_string = { 15c47065977bbe934f8bc14ef8672adf94ac00000017ff9049bbb3464f927eddab0447020071af200863d7e941f0458614bf879acdb9ecbe964c2ea36c5d430a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
