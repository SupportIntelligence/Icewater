import "hash"

rule n3e9_16bb25a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16bb25a1c2000912"
     cluster="n3e9.16bb25a1c2000912"
     cluster_size="586 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ac8c895a46e681085f8bc42af51b653f', 'bb57f4f690f181184b5322755e14fae1', '17e35333876ed56c2f7a82ec9b8bd8e0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(100864,1024) == "67f2b9682a09d09611240adeecd10747"
}

