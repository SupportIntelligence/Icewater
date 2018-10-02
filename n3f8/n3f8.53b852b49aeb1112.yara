
rule n3f8_53b852b49aeb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.53b852b49aeb1112"
     cluster="n3f8.53b852b49aeb1112"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos vmvol piom"
     md5_hashes="['4b4008970dbcf3056218a4b3a2a5a818d2f77e12','7d8ddfde11adbdba83a45ec7ebbae2233a585c9d','c1aefaaf7cead871df602e316bc96f1e851715d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.53b852b49aeb1112"

   strings:
      $hex_string = { 020b13000013039d0182130000140384015c0f00001603cc02ad10000017036104260c000017033a056c0f0000170361044211000018037805110d0000180374 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
