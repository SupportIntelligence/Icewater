
rule n26bb_4b9cea49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b9cea49c0000b12"
     cluster="n26bb.4b9cea49c0000b12"
     cluster_size="97"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic bbdf downware"
     md5_hashes="['e1348704a29ff5fd56143c970d2050a6a97b2fea','e6160d55b74c6d37068b5c3f72c79a4b770a8a79','f85f1da35fb378bd61271ac90213e6eeed78f15c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b9cea49c0000b12"

   strings:
      $hex_string = { 4c2cb216aa36429a96e2a3ad541723cec046b9a80bfe4ffa5c15721491fbfd58ca94737e926e84d1b6e9f078ae6bcd1ae102dcb811873021a98c40ff06198574 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
