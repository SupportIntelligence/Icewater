import "hash"

rule n3ed_51996b46fa211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b46fa211932"
     cluster="n3ed.51996b46fa211932"
     cluster_size="74 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['79395cd08aa1375da3ab36bcccabb331', 'ea2e8139ebd8a7047db7cd34699c5b5d', 'cdf83a26e991c80f38cf16f5e16e89b4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(452608,1024) == "0ddef2dd9490e351383cfa60e754d5ae"
}

