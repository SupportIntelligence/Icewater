import "hash"

rule n3e9_49b6b665c6210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49b6b665c6210b32"
     cluster="n3e9.49b6b665c6210b32"
     cluster_size="2189 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qqpass kazy riskware"
     md5_hashes="['21467fce330106467432b46267334bd8', '030c016fcaab6c81dda061b5e8940265', '03ca7a203ff0c8b9fc409aabed23b236']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(263680,1110) == "5a6f393c17a0b0ad6d2b1bbeb57217ea"
}

