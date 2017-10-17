import "hash"

rule o3e9_43b0cba3c2001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0cba3c2001912"
     cluster="o3e9.43b0cba3c2001912"
     cluster_size="38 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d4bdfe73e94af625ef3c0d8435022212', 'd29f8929402413240bb45f46c1e127ae', 'ab32604361e980b920859e161377ed60']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(728064,1024) == "5a8bb2aaca9ef9a64ba5999efac659f3"
}

