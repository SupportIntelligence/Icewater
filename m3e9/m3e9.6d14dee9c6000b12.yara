import "hash"

rule m3e9_6d14dee9c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6000b12"
     cluster="m3e9.6d14dee9c6000b12"
     cluster_size="699 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi swisyn abzf"
     md5_hashes="['4255aacbd12d62d8edb651989e982f2c', '278c8741be6d840bdfd585248b7b98ee', 'a67d8ad70c063a743704cf20d0e42f19']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

