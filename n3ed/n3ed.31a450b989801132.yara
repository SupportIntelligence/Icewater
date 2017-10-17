import "hash"

rule n3ed_31a450b989801132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a450b989801132"
     cluster="n3ed.31a450b989801132"
     cluster_size="30 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d845c9ec5d67310270d3b538089187b6', 'cdfc96b74653cedc11571270e641f7e7', 'a821dd8e884b75b63e8c748651e98961']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(199680,1024) == "494ca29c111fe1e5f008c4abb7f6b854"
}

