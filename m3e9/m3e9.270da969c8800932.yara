import "hash"

rule m3e9_270da969c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.270da969c8800932"
     cluster="m3e9.270da969c8800932"
     cluster_size="137 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef malicious"
     md5_hashes="['e4f854b69469d11b18f8d0fff9cbdcce', 'c8431b1278dde1362c73ac4246c2a98d', 'b2c4c1cdac1642532fa78a99dfc373fa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(56320,1024) == "0e89da05dd174eed4f40b620f69264b2"
}

