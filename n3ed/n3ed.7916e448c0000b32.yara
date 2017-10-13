import "hash"

rule n3ed_7916e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7916e448c0000b32"
     cluster="n3ed.7916e448c0000b32"
     cluster_size="270 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['f5082f8bea8598257b5ef477a90a8c50', '610f56c5b65a38dce0def488256ca8b0', 'a6b35e27c910c164465ed67095ddb43e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "fad5720205df679ea754faf4b0429215"
}

