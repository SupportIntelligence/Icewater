import "hash"

rule n3e9_59314b56d6c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59314b56d6c31912"
     cluster="n3e9.59314b56d6c31912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jacard yantai malicious"
     md5_hashes="['8d037950a254240e22d8c0bba45406a6', '4d1e8b9f65eafa80c4c84595345bba80', '9d27a3cc6f47951fc36542a8b28800c8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(599402,1039) == "66d1c4f89625471ca39d97192d582de5"
}

