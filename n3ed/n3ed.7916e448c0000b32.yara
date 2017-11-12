import "hash"

rule n3ed_7916e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7916e448c0000b32"
     cluster="n3ed.7916e448c0000b32"
     cluster_size="398 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['df5fef8afa31b3fa543cfcc187b72faf', '65f735d1aea0c64f5e410e19583aa9d9', 'a6efb39d41a08f9bbc8937a3f609bddb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "fad5720205df679ea754faf4b0429215"
}

