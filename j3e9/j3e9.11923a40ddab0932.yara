import "hash"

rule j3e9_11923a40ddab0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.11923a40ddab0932"
     cluster="j3e9.11923a40ddab0932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pakes jnyb fakeav"
     md5_hashes="['2067c05973ab1cfea8eb9907bb346abe','ab8ab0cc302d6fe3b8b6967a903e2c55','f32956ff68985510d218ff15765a5016']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(65536,65536) == "7f7ea7e6a02103b5cc8630c8a780c71a"
}

