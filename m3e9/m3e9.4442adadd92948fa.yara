import "hash"

rule m3e9_4442adadd92948fa
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4442adadd92948fa"
     cluster="m3e9.4442adadd92948fa"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['3ec52bf08bfc1be48111ad0105c3739c', '10c939cf305f23f92ab6c5db50921c17', 'd585614755c56d808b97ac7a2fc9b483']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(214016,1024) == "ae8ec6bffbee0630d15a8af204a454f0"
}

