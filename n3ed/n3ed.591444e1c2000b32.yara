import "hash"

rule n3ed_591444e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591444e1c2000b32"
     cluster="n3ed.591444e1c2000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['bdace7f5def47f4596c7a8c7f9f93a3f', 'd20a4d34f6e6bd1df7b418a750777dfb', 'bdace7f5def47f4596c7a8c7f9f93a3f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

