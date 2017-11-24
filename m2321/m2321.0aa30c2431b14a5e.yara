
rule m2321_0aa30c2431b14a5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0aa30c2431b14a5e"
     cluster="m2321.0aa30c2431b14a5e"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['02d020ed3d155cce47ddf9853e277ef6','35fd29b140f5a317f5dfe3b5209f6735','fb2eb19a07092c4680361f6ba3790905']"

   strings:
      $hex_string = { 67840dcd0fd6d9b12f5e532917e6709a2e6aaa514f8991ac0626c6f8f6b2bd3dbee84388dacbdd16f14028492045af4b8e12a765f7b4796c7a07808d333a5ff2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
