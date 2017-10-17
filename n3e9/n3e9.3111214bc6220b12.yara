import "hash"

rule n3e9_3111214bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3111214bc6220b12"
     cluster="n3e9.3111214bc6220b12"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virlock nabucur polyransom"
     md5_hashes="['374940d05e2974553a49adfc3d472c12', '5b5d316604f6263187b79332fc3e979e', '374940d05e2974553a49adfc3d472c12']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(1024,1024) == "2ac7073c4760c8282ebf1340bb64ca5f"
}

