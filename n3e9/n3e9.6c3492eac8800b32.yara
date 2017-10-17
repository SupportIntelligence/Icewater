import "hash"

rule n3e9_6c3492eac8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6c3492eac8800b32"
     cluster="n3e9.6c3492eac8800b32"
     cluster_size="1058 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="krypt scar ainslot"
     md5_hashes="['4cfd0e42b319e700aaeea49834f2e83d', '55f0ca27e06627ee22e8f5c758828fa0', '6393a481eadd28e2d844e39bf77ba5ef']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(10240,1024) == "9e735e2fe96e61a0bc6566c945ef81b8"
}

