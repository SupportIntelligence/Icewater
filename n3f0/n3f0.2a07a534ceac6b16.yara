import "hash"

rule n3f0_2a07a534ceac6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.2a07a534ceac6b16"
     cluster="n3f0.2a07a534ceac6b16"
     cluster_size="1623 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious filerepmalware amonetize"
     md5_hashes="['29eea26f89a20c64336b02729eb69218', '23b10d7850e659487cf1808781ba66a8', '1767d458b301f4c7ddd687917914c8a9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(794568,1080) == "34ad3daf3f9b609170d3e620c97f44d6"
}

