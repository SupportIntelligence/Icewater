import "hash"

rule m3e9_291492cfc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.291492cfc2220b12"
     cluster="m3e9.291492cfc2220b12"
     cluster_size="736 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cripack tinba highconfidence"
     md5_hashes="['62706b6ba7cd95d11a2c85ad1e9d0d72', '3f89aa7d6a15f98831c8eaf419078c14', 'a11dce36747f22830c2ace65c4a4d110']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(94294,1067) == "0559b04fa69f4ced27c969e7f6e5b56d"
}

