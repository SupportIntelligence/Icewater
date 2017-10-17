import "hash"

rule k3e9_1c1a3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c1a3ac9c4000b14"
     cluster="k3e9.1c1a3ac9c4000b14"
     cluster_size="249 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy simbot backdoor"
     md5_hashes="['c61e0a12ced0f56ee71b753fda5e2fd1', 'aa94674cfb796b0e2f0b290e885e71e0', 'acf450fb1badee9856daaec0f427d574']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

