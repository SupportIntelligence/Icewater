import "hash"

rule n3e9_2b1cde2cdec30b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1cde2cdec30b10"
     cluster="n3e9.2b1cde2cdec30b10"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mikey malicious ransom"
     md5_hashes="['aaaa93606619237c0b938b72ddada2f7', '3f25c141241d4a7eabc0f65b23ec958b', 'de82b775b4774a4c380f582b0e94e08a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(507904,1024) == "dd095203c8d3b392aa5f156357dc3f38"
}

