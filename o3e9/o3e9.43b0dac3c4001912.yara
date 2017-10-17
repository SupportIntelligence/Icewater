import "hash"

rule o3e9_43b0dac3c4001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0dac3c4001912"
     cluster="o3e9.43b0dac3c4001912"
     cluster_size="556 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c0f85c4c2fb6359a2ec9133530b909ec', 'dcbd81b620a8ac92fcdff7c8a1eab759', 'e387616a0e2cc6babb901bdefc24b04f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

