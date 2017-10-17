import "hash"

rule n3e9_49982d4bc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49982d4bc6620b16"
     cluster="n3e9.49982d4bc6620b16"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['6c7662788fb5279abb440d08c68e4684', '7970c9c6c80c9b4d8e9bd20dcb8de17d', 'a6385e770095541353b2db069c12e0c3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(108544,1024) == "9650727afb29740793894269db598dc4"
}

