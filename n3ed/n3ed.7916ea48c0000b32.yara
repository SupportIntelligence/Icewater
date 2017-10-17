import "hash"

rule n3ed_7916ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7916ea48c0000b32"
     cluster="n3ed.7916ea48c0000b32"
     cluster_size="242 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a712e23813c5602d2ff2765db621414c', 'cd6572d3a3bd5e2584c165a7323afd1b', 'df78b810dbad1f333df477a636ab0cf7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(24576,1024) == "e390911f222e451fe7dc50df7ef1e195"
}

