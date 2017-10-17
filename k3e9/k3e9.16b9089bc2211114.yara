import "hash"

rule k3e9_16b9089bc2211114
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.16b9089bc2211114"
     cluster="k3e9.16b9089bc2211114"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy simbot backdoor"
     md5_hashes="['0b7f1d5860c4cbd7edca81437d77a8aa', '0b7f1d5860c4cbd7edca81437d77a8aa', '0b7f1d5860c4cbd7edca81437d77a8aa']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "b619018a17a8dedadb7a2ed648bb587d"
}

