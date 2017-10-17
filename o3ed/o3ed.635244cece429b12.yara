import "hash"

rule o3ed_635244cece429b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece429b12"
     cluster="o3ed.635244cece429b12"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['931859eb4e2b72f6e210080f7bfc7835', 'bd17b3ae7bbdfcb658675038dc53ab01', '931859eb4e2b72f6e210080f7bfc7835']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2711552,1024) == "b76cb8f54dcda147685e3a189523f6b0"
}

