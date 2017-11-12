import "hash"

rule j3e9_693c67242db96d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.693c67242db96d92"
     cluster="j3e9.693c67242db96d92"
     cluster_size="1915"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot upatre trojandownloader"
     md5_hashes="['00a9ce9b9acebef0bbe42b6fd411199d','00cd671d31991044c2f917013d8d7bd5','04c013640277a2e1ab66dc1fe3349ce2']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "4ec3ff846d8f1d3a306bce1235b81919"
}

