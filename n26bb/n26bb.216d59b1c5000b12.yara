
rule n26bb_216d59b1c5000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.216d59b1c5000b12"
     cluster="n26bb.216d59b1c5000b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['88e09d6bad558978342536d3edf5f4f016f2c647','0ce838d2abc10ca0cc7180a5c37c22739cc3a612','b023c55747cb44b47455381963d6e04adea882f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.216d59b1c5000b12"

   strings:
      $hex_string = { 3bc5f72eddb4548b3c75794d9ab59d466b585d57282453c79c5960042133befaf265f3de2c30b3ee34a822c99339e5696eedff78989f001ca3f0f8d01b8c202b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
