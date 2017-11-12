import "hash"

rule j3e9_29b33a40ddab1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.29b33a40ddab1912"
     cluster="j3e9.29b33a40ddab1912"
     cluster_size="19"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pakes jnyb fakeav"
     md5_hashes="['14b377a91e9793ad7dbe088547e26f4e','1a847a51ba65be0bc4d3ed32bc7c8529','e1c32382d4ed78d9174bf012ec13161b']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(65536,65536) == "7f7ea7e6a02103b5cc8630c8a780c71a"
}

