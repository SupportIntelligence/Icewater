import "hash"

rule o3ed_4d96c7a9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96c7a9c4000b12"
     cluster="o3ed.4d96c7a9c4000b12"
     cluster_size="109 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c8e6e9bb89e5994e142de5067de65d67', '52c265bb55afc8d44af1f6e59a5ba519', '52c265bb55afc8d44af1f6e59a5ba519']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1173504,1024) == "79a0ca033e9476bdf570bdd896445f12"
}

