import "hash"

rule p3ed_1193a849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.1193a849c0000912"
     cluster="p3ed.1193a849c0000912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wanna exploit"
     md5_hashes="['22586168673c8532e35f19f404afff75', '0ab45fc185ce76c68ce9ba96b3f02d08', 'd3f704dd94cc8d5e952b29cbcf45bdd0']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4096,1024) == "96805fafcac9dc0b8a60e5df785ff2e4"
}

