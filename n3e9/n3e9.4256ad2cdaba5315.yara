import "hash"

rule n3e9_4256ad2cdaba5315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4256ad2cdaba5315"
     cluster="n3e9.4256ad2cdaba5315"
     cluster_size="4090 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['250ac095002c86903c691d0e5143b458', '35880a09cb8af14df322f2322faed964', '022787e727f64cd4375f35d798dcac39']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(712704,1024) == "6e9d1f71c4fc1d15075704839d17b462"
}

