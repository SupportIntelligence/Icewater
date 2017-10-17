import "hash"

rule n3ed_53163949c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53163949c8000b16"
     cluster="n3ed.53163949c8000b16"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['8e0dc5667ada0a727a3a6114b3da44f9', 'b34e30bedc306def0888263476424b8f', 'dd5acb19bc8bdef09f6f9fe2e0f7f93d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

