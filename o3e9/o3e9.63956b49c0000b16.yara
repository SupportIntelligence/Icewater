import "hash"

rule o3e9_63956b49c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.63956b49c0000b16"
     cluster="o3e9.63956b49c0000b16"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor trojandropper malicious"
     md5_hashes="['a5a5f7af657830a3bff44a39de2e4f9e', 'bf1f0bda5ceb159cd3e501207a21cb76', 'd504de3ee5efe31f1552b5c7ae42d74f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(12288,1024) == "364f50a36b1937f39df27a37a04c36bc"
}

