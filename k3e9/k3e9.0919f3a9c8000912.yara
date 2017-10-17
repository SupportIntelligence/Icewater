import "hash"

rule k3e9_0919f3a9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0919f3a9c8000912"
     cluster="k3e9.0919f3a9c8000912"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy injector backdoor"
     md5_hashes="['c0b74b24c45dc66eccea84bedeb33478', '379894c9cb29d43b4de2c319f1c0704e', 'c0b74b24c45dc66eccea84bedeb33478']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

