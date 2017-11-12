import "hash"

rule n3e9_31ba292bd8eb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bd8eb0932"
     cluster="n3e9.31ba292bd8eb0932"
     cluster_size="1998 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor darkkomet fynloski"
     md5_hashes="['6b308fd7ebf238dae424f175255a3f61', '3d43422d533f18bbf031ed62a2cc8161', '006353c970fd716bc24ef706104c7c5e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(630272,1024) == "b4f185c39e9f1bdee3a3d63012d57f58"
}

