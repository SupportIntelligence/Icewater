
rule k3e9_0a78aa46166f4cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0a78aa46166f4cba"
     cluster="k3e9.0a78aa46166f4cba"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['11e2e97c1548f28dbceb5fa2d3bf70bc','127ffbc2e4d15f845b28fed191784da1','b842c19f5690155e07e8f4405def758e']"

   strings:
      $hex_string = { 41b5fcd7c6ed63ea98a8f8850bbcd69c03968a130ef497eb7f91372cc43fda0f7277821c9d951fbbff352eaa10d0834c16a4fd7a6c134b062f34f268e738b615 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
