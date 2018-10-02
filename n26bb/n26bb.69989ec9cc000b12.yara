
rule n26bb_69989ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.69989ec9cc000b12"
     cluster="n26bb.69989ec9cc000b12"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['16270e9db025a4d7bc98481f41ac36ae9fa7d114','86d1ed5897e258100e29658371d813a34b9a6c19','607b25a63e1fa7e71779a86d611d2dfe25aff7e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.69989ec9cc000b12"

   strings:
      $hex_string = { 51e1826a4eda95c92bf5c3ab96c42d014143ea27978436b18ceb4808a73dd560934ad616337ba494c2ee4bd96b4c7c5ca35bd05f180df78a1edda53fbfe93024 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
