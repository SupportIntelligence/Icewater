
rule m2321_0aab0c25b1b14a5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0aab0c25b1b14a5e"
     cluster="m2321.0aab0c25b1b14a5e"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['04278a15f6cd613eef505f737c43d6ab','22a0763f1866da7329ceb31d2bfcd066','ec202c2f326ede91ef38e9518315d301']"

   strings:
      $hex_string = { 67840dcd0fd6d9b12f5e532917e6709a2e6aaa514f8991ac0626c6f8f6b2bd3dbee84388dacbdd16f14028492045af4b8e12a765f7b4796c7a07808d333a5ff2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
