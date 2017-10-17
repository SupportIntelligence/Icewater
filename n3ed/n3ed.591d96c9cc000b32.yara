import "hash"

rule n3ed_591d96c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591d96c9cc000b32"
     cluster="n3ed.591d96c9cc000b32"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['25846d4194799a141851162785db248b', 'bff9e57b5d3ce7b193df497598cc014c', 'bff9e57b5d3ce7b193df497598cc014c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

