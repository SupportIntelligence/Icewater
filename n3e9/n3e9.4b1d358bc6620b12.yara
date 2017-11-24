
rule n3e9_4b1d358bc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b1d358bc6620b12"
     cluster="n3e9.4b1d358bc6620b12"
     cluster_size="35"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['0c40386c44af3698a8ad1c410d4dd999','2913316607a14681afde544f05b13181','c531d380bafff33e673fe94440d960f9']"

   strings:
      $hex_string = { 67840dcd0fd6d9b12f5e532917e6709a2e6aaa514f8991ac0626c6f8f6b2bd3dbee84388dacbdd16f14028492045af4b8e12a765f7b4796c7a07808d333a5ff2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
