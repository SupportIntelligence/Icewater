
rule n3ed_35949399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.35949399c2200b12"
     cluster="n3ed.35949399c2200b12"
     cluster_size="123"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['0b070fb2bb2981c11089cdfa6a65bd6a','0b40ca217d8169b91f55c74c8f33d13a','54e29040e542830330d91671183a4e49']"

   strings:
      $hex_string = { 00292e43c9a2d87c013d3654a1ecf0061362a705f3c0c7738c98932bd9bc4c82ca1e9b573cfdd4e01667426f188a17e512be4ec4d6da9ede49a0fbf58ebb2fee }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
