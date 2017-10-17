import "hash"

rule n3ed_31a49ec148001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a49ec148001132"
     cluster="n3ed.31a49ec148001132"
     cluster_size="211 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c850837eb5e9bf66563f6931a2852c39', 'f2279d184a73d0b35f8dcc154f919010', 'aa15d3ae9aeb168d363efcaa2f4f7dfc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(185344,1024) == "fe0380eba02c5234e3a403b108588d1d"
}

