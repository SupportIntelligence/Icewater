import "hash"

rule k3e9_6164a9bd21146796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6164a9bd21146796"
     cluster="k3e9.6164a9bd21146796"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['62b3d4aebaf1327d080d6916d3d3399a', '62b3d4aebaf1327d080d6916d3d3399a', '62b3d4aebaf1327d080d6916d3d3399a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(30720,1536) == "998bd0f9a481d7ca15babd6b6e646134"
}

