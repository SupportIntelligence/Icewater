
rule n2321_11966848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.11966848c0000b32"
     cluster="n2321.11966848c0000b32"
     cluster_size="22"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['02b71d6b5f5f1916e77b884a5f563369','05609db60f73be8dfaa1b7550b9f48bf','8bed3410b6efff206a06eade263ae001']"

   strings:
      $hex_string = { 67840dcd0fd6d9b12f5e532917e6709a2e6aaa514f8991ac0626c6f8f6b2bd3dbee84388dacbdd16f14028492045af4b8e12a765f7b4796c7a07808d333a5ff2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
