import "hash"

rule j3e9_0b9d2b46ccb4eb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.0b9d2b46ccb4eb12"
     cluster="j3e9.0b9d2b46ccb4eb12"
     cluster_size="1360"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bublik generickd"
     md5_hashes="['0036f9b99aaba55a7789c617c6658245','00d72ef02f362f1c9582c979fc3f2f05','0a9b4bf00a209514942c37bbdaee2684']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(0,4096) == "8034e607d053f9f7dcebef18ca3cbe5a"
}

