import "hash"

rule m3e9_5d1c8c8cd69ae332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5d1c8c8cd69ae332"
     cluster="m3e9.5d1c8c8cd69ae332"
     cluster_size="308 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef wbna"
     md5_hashes="['8238266714847a0938ea513c6a76454c', 'ac73ab52b26aaeff2c5ea61924658eff', '835b04e1afd55679a282241734e9811d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(199680,1024) == "2f157ccac6fe94e8a49d4159a767f079"
}

