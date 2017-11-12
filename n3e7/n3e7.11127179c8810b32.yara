
rule n3e7_11127179c8810b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.11127179c8810b32"
     cluster="n3e7.11127179c8810b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide malicious applicunsaf"
     md5_hashes="['28ae10c8459672dba7756986b770ad24','42b9a551439bdd9226da23e5a3eba3ec','fa34b74b8259a51094206f5f8a9bed00']"

   strings:
      $hex_string = { e68ebb61b33e5a2254346afdfbdf1f92979f19ea52387281741acb56a745c6a2ffe5c9a3888f3dc964ca59a1c5764263653296021d5574f5f62d9ebe3f77e320 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
