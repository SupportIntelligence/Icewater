
rule n3e9_2504ea49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2504ea49c0000b32"
     cluster="n3e9.2504ea49c0000b32"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['15f1aab4410e671728764e7b0bb16d82','a2f3a43dca40d39b9fdecb97b6a8197b','d96d817b8a36263f88bc300229c2815e']"

   strings:
      $hex_string = { 00009ea5c6027c7e883fa0a0a0c8dcdcdcfff4f4f4fefdfdfdfff8f9fefec7cff9fe6d82f1fe1f41eaff2344eafe4763eefe6e84f1ff8093f2fe8799f3fe899b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
