import "hash"

rule k3e9_56a919b946201114
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.56a919b946201114"
     cluster="k3e9.56a919b946201114"
     cluster_size="296 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy rubinurd small"
     md5_hashes="['3a6af9456470e81f03a78b9daa0895ff', 'abccd49185472257520f6969b41af622', 'c16b7fb95fa02ab81725309fb6308d59']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "2b75e03ba80408ac5917d1e4af2d3085"
}

