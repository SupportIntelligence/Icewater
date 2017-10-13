import "hash"

rule n3ed_51996b44dec31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b44dec31932"
     cluster="n3ed.51996b44dec31932"
     cluster_size="42 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['7c81d437b23a0c89f5deb4be24ba82b0', 'cee5a7f5381983a466ae74cf42c57f4b', 'd0a5f8dc6b88c47008a9c6dba0afc005']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(452608,1024) == "0ddef2dd9490e351383cfa60e754d5ae"
}

