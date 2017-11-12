import "hash"

rule n3ed_595385abc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.595385abc6620b32"
     cluster="n3ed.595385abc6620b32"
     cluster_size="1009 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['7b61e4594c8b0026f1bb458ea1f09e27', '50e4eee6ae4ce62d76843728add7f8ea', '6f84bc87a85037a012fb1ed4083ffa35']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

