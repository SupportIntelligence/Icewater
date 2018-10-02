
rule n26ef_1b14a524a74f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.1b14a524a74f4b12"
     cluster="n26ef.1b14a524a74f4b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner malicious"
     md5_hashes="['e5568f2e066a697816f9dcb8d402b7d2b68c0aa7','cef1d61bb3a75103908ab3853f16ce65ccc076e6','011d636fd9fb644236bdb63cfad109c7c7209d7f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.1b14a524a74f4b12"

   strings:
      $hex_string = { 010fb60430418846024983c60348b8fdce61841177ccab48f7e5488bfa48c1ef1a69c700e1f5052be8b85917b7d1f7e7448bda41c1eb0d4169c3102700002bf8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
