import "hash"

rule n3ed_39857a46dfd31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a46dfd31932"
     cluster="n3ed.39857a46dfd31932"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ade62aaa07fa37d32bbfadba871afddc', '17a762069380de009928c3fa276f0882', 'ade62aaa07fa37d32bbfadba871afddc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(362496,1024) == "2c262d66b505baf68ab3851e94a5ba11"
}

