import "hash"

rule n3e9_4cbd625ad5eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4cbd625ad5eb0b12"
     cluster="n3e9.4cbd625ad5eb0b12"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="filerepmalware malicious tovkater"
     md5_hashes="['37cda45a14eda7268bd3e9df39d2ddc9', 'cf8842f23d222f7ebc6b81c8b5e64b55', '0dc479dd6ab732c56bba8835c1106cd3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(301728,1025) == "3d3239a09b5a5b66e7f9b3a0540bb564"
}

