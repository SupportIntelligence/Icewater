import "hash"

rule k3e9_1b294366cdd39112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b294366cdd39112"
     cluster="k3e9.1b294366cdd39112"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['ae3ea8f3366e4799feaa746fb0d7e955', 'a076103bb1e2040a0a15e1ef0310b4a9', '8f974c2f992f66979345da39453781dc']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "0449c30b832c1c60111f03ffa49ccd7d"
}

