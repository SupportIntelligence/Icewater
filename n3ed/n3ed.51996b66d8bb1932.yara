import "hash"

rule n3ed_51996b66d8bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b66d8bb1932"
     cluster="n3ed.51996b66d8bb1932"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ec129fabc43645c272a9b3e1672d1ebf', 'ce9e213b4216e4d9ea3d9845643444c9', 'ce9e213b4216e4d9ea3d9845643444c9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(452608,1024) == "0ddef2dd9490e351383cfa60e754d5ae"
}

