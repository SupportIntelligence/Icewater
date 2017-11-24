
rule k3e9_0b94e448c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b94e448c4000b16"
     cluster="k3e9.0b94e448c4000b16"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['2ebcb72df18a11d3c5ec1ed0d9ade342','404b8cf772b08f59b285552e30a986fe','f68357661a6dc8ce9c6d5d32394c654a']"

   strings:
      $hex_string = { 44f4cd9c631de540b4d8c51e88ff00c3e2f53e3a8bb14624fe9eb8427edff1e4a82d87d6ca5c475ac787ea77d9256eb94513756d27ebbf935dd1f7e8fe10a22c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
