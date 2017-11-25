
rule o3e7_138b2849c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.138b2849c0000b12"
     cluster="o3e7.138b2849c0000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="snojan malicious qjwmonkey"
     md5_hashes="['4cfe2ce6b53316a3910f0b47d2380b91','9bfddb14eb18e63f369e5851d3c2193d','f7ae0d0c08c2a686e184f212e4019b2e']"

   strings:
      $hex_string = { 3f001c31c0a8274d3ab00be518268d05486028f2506f33494ba1c325f8326893304c46d1c9de387680d0946465ff8b0d4a05e6c5b9a6d4befd0c242302eb829f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
