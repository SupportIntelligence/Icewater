import "hash"

rule k3e9_626e25513b2a46b6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.626e25513b2a46b6"
     cluster="k3e9.626e25513b2a46b6"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna chinky vobfus"
     md5_hashes="['ab64d3af91706208427f3f3cb1578827', 'a46bf3f8be65a7c38bd376a62cad8efb', 'b8a42e624f7f392d4d32e77d79c11cbd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(33792,1024) == "62d12b8e3f7c98fabbc5f8c0f7fc5db4"
}

