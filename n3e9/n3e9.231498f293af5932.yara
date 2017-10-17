import "hash"

rule n3e9_231498f293af5932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.231498f293af5932"
     cluster="n3e9.231498f293af5932"
     cluster_size="1598 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt eyestye bffd"
     md5_hashes="['0bc8a3761f0cbb938342bfb86f4ee307', '4eab64531e59656e3ce041f9a5e23d6a', '4ed4ca098115199638740b4b5f4522c6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(586399,1027) == "67be7e1edce76de4fd20d5c7df223d44"
}

