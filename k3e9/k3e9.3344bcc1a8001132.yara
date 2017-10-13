import "hash"

rule k3e9_3344bcc1a8001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3344bcc1a8001132"
     cluster="k3e9.3344bcc1a8001132"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy upatre trojandownloader"
     md5_hashes="['df07171b3e24231dbbdb5032c9f03c4e', '7b38e3bd30ca56995d6f7e69fa34bdbd', 'd219f90e77b03ad441f04a319d275025']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(10240,1536) == "06028690dbb50c780241515e72901842"
}

