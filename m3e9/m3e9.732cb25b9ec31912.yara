import "hash"

rule m3e9_732cb25b9ec31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.732cb25b9ec31912"
     cluster="m3e9.732cb25b9ec31912"
     cluster_size="51 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus wbna conjar"
     md5_hashes="['c3b3fc0b9a1b2c3c38deafa4460acd59', 'bf6376ce62c39db5ef8edf5f56af34b4', '4cd66d80d8f41323c0626de6fc9e3d63']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(132096,1024) == "8d33c67a7b8d3238c3a2456f5af5ddbf"
}

