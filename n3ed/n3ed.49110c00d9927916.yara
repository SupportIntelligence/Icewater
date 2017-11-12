import "hash"

rule n3ed_49110c00d9927916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.49110c00d9927916"
     cluster="n3ed.49110c00d9927916"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi backdoor atraps"
     md5_hashes="['b3ca2aebe36f9f021434997f2b0790f8', 'c5cd751fcababc66d113a842fa6debce', 'a66f0a02a575702f123dbe1178585e84']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(534528,1024) == "a1d288bccd507aecdf5f1e5b2154dc59"
}

