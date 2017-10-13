import "hash"

rule m3e9_631e3689c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e3689c8000b32"
     cluster="m3e9.631e3689c8000b32"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['de78df4ffb2d3d60a6cb4fc9a985e753', '25aa6289268e5d54ce586e2dacabe450', '3a1b2e37c41f0f6e3c74f1c5be95ca24']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62060,1051) == "6b92d4de5a9816ad40ab710f60080201"
}

