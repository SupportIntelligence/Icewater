import "hash"

rule m3f9_4ad9bbacf4bccb96
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.4ad9bbacf4bccb96"
     cluster="m3f9.4ad9bbacf4bccb96"
     cluster_size="1045 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="yakes bitd heuristic"
     md5_hashes="['9ad1b1db72a7612377061aa1d453cfcf', 'a36820755fdf5a84163df19e07153374', '791287c62056e8ba350fdb8a088d4636']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(1559,1047) == "ce32956620d902af6130218b55e00284"
}

